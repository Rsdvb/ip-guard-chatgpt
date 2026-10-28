import Foundation
import NetworkExtension
import Security

final class FlowIdentity: NSObject {
    let path: String?
    let identifier: String?
    let uid: UInt32
    init(path: String?, identifier: String?, uid: UInt32) { self.path = path; self.identifier = identifier; self.uid = uid }
}

final class FilterDataProvider: NEFilterDataProvider {
    private let store = PolicyStore()
    private let identities = NSCache<NSData, FlowIdentity>()
    private var policyListener: PolicyListener?

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        do {
            try store.loadBindings(filterConfiguration.vendorConfiguration?["IPGuardBindings"] as? Data)
            guard let team = codeTeam(),
                  let keys = Bundle.main.object(forInfoDictionaryKey: "NetworkExtension") as? [String: Any],
                  let service = keys["NEMachServiceName"] as? String,
                  service.hasPrefix(team + ".") else { throw PolicyError.invalid }
            let listener = PolicyListener(store: store, team: team); listener.start(name: service); policyListener = listener
            identities.countLimit = 2048
            let rule = NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .any, direction: .outbound)
            apply(NEFilterSettings(rules: [NEFilterRule(networkRule: rule, action: .filterData)], defaultAction: .allow), completionHandler: completionHandler)
        } catch { completionHandler(error) }
    }
    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) { completionHandler() }

    private func identity(_ candidate: Data?) -> FlowIdentity? {
        guard let token = candidate, token.count == 32 else { return nil }
        if let cached = identities.object(forKey: token as NSData) { return cached }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: token] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code = code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode = staticCode else { return nil }
        var location: CFURL?
        let located = SecCodeCopyPath(staticCode, [], &location) == errSecSuccess
        var information: CFDictionary?
        let signed = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess
        let identifier = signed ? (information as? [String: Any])?[kSecCodeInfoIdentifier as String] as? String : nil
        let uid = token.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self) }
        let result = FlowIdentity(path: located ? location.map { ($0 as URL).standardizedFileURL.path } : nil, identifier: identifier, uid: uid)
        identities.setObject(result, forKey: token as NSData); return result
    }
    private func decision(_ flow: NEFilterFlow) -> FilterDecision {
        if let value = identity(flow.sourceProcessAuditToken) {
            let result = value.path.map { store.decision(path: $0, uid: value.uid, now: continuousNow()) } ?? store.unidentifiedApp(identifier: value.identifier, uid: value.uid)
            if result != .unmanaged { return result }
        }
        if let value = identity(flow.sourceAppAuditToken) {
            let result = value.path.map { store.decision(path: $0, uid: value.uid, now: continuousNow()) } ?? store.unidentifiedApp(identifier: value.identifier, uid: value.uid)
            if result != .unmanaged { return result }
        }
        return .unmanaged
    }
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        switch decision(flow) {
        case .unmanaged: return .allow()
        case .block: return .drop()
        case .allow:
            return NEFilterNewFlowVerdict.filterDataVerdict(withFilterInbound: true, peekInboundBytes: Int.max, filterOutbound: true, peekOutboundBytes: Int.max)
        }
    }
    private func dataVerdict(_ flow: NEFilterFlow, count: Int) -> NEFilterDataVerdict {
        switch decision(flow) {
        case .unmanaged: return .allow()
        case .block: return .drop()
        case .allow: return NEFilterDataVerdict(passBytes: count, peekBytes: Int.max)
        }
    }
    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict { dataVerdict(flow, count: readBytes.count) }
    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict { dataVerdict(flow, count: readBytes.count) }
}
