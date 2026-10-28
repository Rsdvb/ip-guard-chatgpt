import Foundation
import Security

@objc protocol IPGuardPolicyChannel {
    func update(_ policy: Data, reply: @escaping (Bool) -> Void)
    func ping(_ reply: @escaping (Bool) -> Void)
}

func codeTeam() -> String? {
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code = code else { return nil }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode = staticCode else { return nil }
    var information: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
          let values = information as? [String: Any] else { return nil }
    return values[kSecCodeInfoTeamIdentifier as String] as? String
}

func validController(_ connection: NSXPCConnection, team: String) -> Bool {
    guard team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil else { return false }
    var code: SecCode?
    let attributes = [kSecGuestAttributePid as String: NSNumber(value: connection.processIdentifier)] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code = code else { return false }
    var requirement: SecRequirement?
    let text = "anchor apple generic and identifier \"com.ip-guard.desktop\" and certificate leaf[subject.OU] = \"\(team)\""
    guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement = requirement else { return false }
    return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
}

final class PolicySession: NSObject, IPGuardPolicyChannel {
    let uid: UInt32
    let peer = UUID()
    let store: PolicyStore
    init(uid: UInt32, store: PolicyStore) { self.uid = uid; self.store = store }
    func update(_ data: Data, reply: @escaping (Bool) -> Void) {
        do { try store.update(data, uid: uid, peer: peer, now: ProcessInfo.processInfo.systemUptime); reply(true) }
        catch { reply(false) }
    }
    func ping(_ reply: @escaping (Bool) -> Void) { reply(true) }
}

final class PolicyListener: NSObject, NSXPCListenerDelegate {
    let store: PolicyStore
    let team: String
    private var listener: NSXPCListener?
    private var connections: [UUID: NSXPCConnection] = [:]
    private let lock = NSLock()
    init(store: PolicyStore, team: String) { self.store = store; self.team = team }
    func start(name: String) {
        let value = NSXPCListener(machServiceName: name); value.delegate = self; value.resume(); listener = value
    }
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard validController(connection, team: team) else { return false }
        lock.lock()
        guard connections.count < 32 else { lock.unlock(); return false }
        let session = PolicySession(uid: connection.effectiveUserIdentifier, store: store)
        connections[session.peer] = connection; lock.unlock()
        connection.exportedInterface = NSXPCInterface(with: IPGuardPolicyChannel.self)
        connection.exportedObject = session
        let lost = { [weak self] in
            guard let self = self else { return }
            self.store.disconnected(uid: session.uid, peer: session.peer)
            self.lock.lock(); self.connections[session.peer] = nil; self.lock.unlock()
        }
        connection.invalidationHandler = lost; connection.interruptionHandler = lost
        connection.resume(); return true
    }
}
