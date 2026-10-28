import Foundation

struct FilterTarget: Codable, Equatable {
    let id: String
    let service: String
    let executable: String
    let bundleRoot: String?
    let allowed: Bool

    func validate() throws {
        guard UUID(uuidString: id) != nil, ["claude", "chatgpt"].contains(service),
              executable.hasPrefix("/"), executable.utf8.count <= 4096,
              !executable.contains("\0"), URL(fileURLWithPath: executable).standardizedFileURL.path == executable else {
            throw PolicyError.invalid
        }
        if let root = bundleRoot {
            guard root.hasSuffix(".app"), executable.hasPrefix(root + "/Contents/"),
                  URL(fileURLWithPath: root).standardizedFileURL.path == root else { throw PolicyError.invalid }
        }
    }
    func matches(_ path: String) -> Bool {
        executable == path || bundleRoot.map { path == $0 || path.hasPrefix($0 + "/") } == true
    }
    var binding: FilterTarget { FilterTarget(id: id, service: service, executable: executable, bundleRoot: bundleRoot, allowed: false) }
}

enum PolicyError: Error { case invalid }
struct FilterPolicy: Codable {
    let format: Int
    let uid: UInt32
    let targets: [FilterTarget]
    static func decode(_ data: Data, uid: UInt32) throws -> FilterPolicy {
        guard data.count <= 524288 else { throw PolicyError.invalid }
        let value = try JSONDecoder().decode(FilterPolicy.self, from: data)
        guard value.format == 1, value.uid == uid, value.targets.count <= 256,
              Set(value.targets.map(\.id)).count == value.targets.count else { throw PolicyError.invalid }
        for target in value.targets { try target.validate() }
        for left in value.targets {
            for right in value.targets where left.service != right.service {
                if left.matches(right.executable) || right.matches(left.executable) { throw PolicyError.invalid }
            }
        }
        return value
    }
}

enum FilterDecision { case unmanaged, allow, block }
final class PolicyStore {
    private let lock = NSLock()
    private var targets: [UInt32: [FilterTarget]] = [:]
    private var deadlines: [UInt32: TimeInterval] = [:]
    private var peers: [UInt32: UUID] = [:]

    func loadBindings(_ data: Data?) throws {
        guard let data = data else { return }
        guard data.count <= 1048576 else { throw PolicyError.invalid }
        let entries = try JSONDecoder().decode([String: [FilterTarget]].self, from: data)
        var result: [UInt32: [FilterTarget]] = [:]
        for (key, values) in entries {
            guard let uid = UInt32(key), values.count <= 256 else { throw PolicyError.invalid }
            let encoded = try JSONEncoder().encode(FilterPolicy(format: 1, uid: uid, targets: values))
            result[uid] = try FilterPolicy.decode(encoded, uid: uid).targets.map(\.binding)
        }
        lock.lock(); defer { lock.unlock() }
        targets = result; deadlines = [:]; peers = [:]
    }
    func update(_ data: Data, uid: UInt32, peer: UUID, now: TimeInterval) throws {
        let policy = try FilterPolicy.decode(data, uid: uid)
        lock.lock(); defer { lock.unlock() }
        targets[uid] = policy.targets; peers[uid] = peer; deadlines[uid] = now + 3.5
    }
    func disconnected(uid: UInt32, peer: UUID) {
        lock.lock(); defer { lock.unlock() }
        if peers[uid] == peer { deadlines[uid] = nil; peers[uid] = nil }
    }
    func decision(path: String, uid: UInt32, now: TimeInterval) -> FilterDecision {
        lock.lock(); defer { lock.unlock() }
        let matching = (targets[uid] ?? []).filter { $0.matches(path) }
        if matching.isEmpty { return .unmanaged }
        return deadlines[uid].map { now <= $0 } == true && matching.allSatisfy(\.allowed) ? .allow : .block
    }
    var hasTargets: Bool {
        lock.lock(); defer { lock.unlock() }; return targets.values.contains { !$0.isEmpty }
    }
}
