import Foundation

@main enum PolicyTests {
    static func main() throws {
        let uid: UInt32 = 501
        let store = PolicyStore(), peer = UUID()
        let claude = FilterTarget(id: UUID().uuidString, service: "claude", executable: "/Applications/Claude.app/Contents/MacOS/Claude", bundleRoot: "/Applications/Claude.app", allowed: true)
        let gpt = FilterTarget(id: UUID().uuidString, service: "chatgpt", executable: "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", bundleRoot: "/Applications/ChatGPT.app", allowed: false)
        let policy = FilterPolicy(format: 1, uid: uid, targets: [claude, gpt], sequence: 1)
        let data = try JSONEncoder().encode(policy)
        try store.update(data, uid: uid, peer: peer, now: 100)
        precondition(store.decision(path: claude.executable, uid: uid, now: 101) == .allow)
        precondition(store.decision(path: gpt.executable, uid: uid, now: 101) == .block)
        precondition(store.decision(path: "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app", uid: uid, now: 101) == .allow)
        precondition(store.decision(path: "/Applications/Claude.app.evil/Contents/MacOS/Claude", uid: uid, now: 101) == .unmanaged)
        precondition(store.decision(path: claude.executable, uid: 502, now: 101) == .unmanaged)
        precondition(store.decision(path: claude.executable, uid: uid, now: 104) == .block)
        var wrongUID = false
        do { try store.update(data, uid: 502, peer: peer, now: 100) } catch { wrongUID = true }
        precondition(wrongUID)
        var renewed = policy; renewed.sequence = 2
        try store.update(try JSONEncoder().encode(renewed), uid: uid, peer: peer, now: 110)
        store.disconnected(uid: uid, peer: UUID())
        precondition(store.decision(path: claude.executable, uid: uid, now: 111) == .allow)
        store.disconnected(uid: uid, peer: peer)
        precondition(store.decision(path: claude.executable, uid: uid, now: 111) == .block)
        let saved = try JSONEncoder().encode([String(uid): [claude.binding, gpt.binding]])
        try store.loadBindings(saved)
        precondition(store.decision(path: claude.executable, uid: uid, now: 1) == .block)
        let replayStore = PolicyStore()
        guard var fields = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { preconditionFailure("Invalid test envelope") }
        fields["sequence"] = 1
        let sequenced = try JSONSerialization.data(withJSONObject: fields)
        try replayStore.update(sequenced, uid: uid, peer: peer, now: 120)
        var competingRejected = false
        do { try replayStore.update(sequenced, uid: uid, peer: UUID(), now: 120.5) } catch { competingRejected = true }
        precondition(competingRejected, "A competing live controller must not replace the active user's policy")
        var replayRejected = false
        do { try replayStore.update(sequenced, uid: uid, peer: peer, now: 121) } catch { replayRejected = true }
        precondition(replayRejected, "A repeated policy revision must not renew a network grant")
        print("PASS Swift filter policy: independent services, UID isolation, bundle boundaries, heartbeat expiry, disconnect and persisted deny defaults")
    }
}
