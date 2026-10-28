import Foundation
import NetworkExtension
import Security

final class FlowIdentity: NSObject {
    let path: String
    let uid: UInt32
    init(path: String, uid: UInt32) { self.path = path; self.uid = uid }
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

    private func identity(_ flow: NEFilterFlow) -> FlowIdentity? {
        guard let token = flow.sourceAppAuditToken, token.count == 32 else { return nil }
        if let cached = identities.object(forKey: token as NSData) { return cached }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: token] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code = code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode = staticCode else { return nil }
        var location: CFURL?
        guard SecCodeCopyPath(staticCode, [], &location) == errSecSuccess, let location = location else { return nil }
        let uid = token.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self) }
        let result = FlowIdentity(path: (location as URL).standardizedFileURL.path, uid: uid)
        identities.setObject(result, forKey: token as NSData); return result
    }
    private func decision(_ flow: NEFilterFlow) -> FilterDecision {
        guard let value = identity(flow) else { return store.hasTargets ? .block : .unmanaged }
        return store.decision(path: value.path, uid: value.uid, now: ProcessInfo.processInfo.systemUptime)
    }
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        switch decision(flow) {
        case .unmanaged: return .allow()
        case .block: return .drop()
        case .allow:
            return NEFilterNewFlowVerdict(filterInbound: true, peekInboundBytes: Int.max, filterOutbound: true, peekOutboundBytes: Int.max)
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
