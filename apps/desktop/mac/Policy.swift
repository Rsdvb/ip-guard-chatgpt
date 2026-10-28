import Foundation
import Darwin

private let continuousScale: Double = {
    var info = mach_timebase_info_data_t(); mach_timebase_info(&info)
    return Double(info.numer) / Double(info.denom) / 1_000_000_000
}()
func continuousNow() -> TimeInterval { Double(mach_continuous_time()) * continuousScale }

struct FilterTarget: Codable, Equatable {
    let id: String
    let service: String
    let executable: String
    let bundleRoot: String?
    let allowed: Bool
    var keepRunning: Bool? = nil
    var aliases: [String]? = nil
    var bundleIdentifier: String? = nil

    var paths: [String] { [executable] + (aliases ?? []) }
    func validate() throws {
        guard UUID(uuidString: id) != nil, ["claude", "chatgpt"].contains(service), paths.count <= 17 else { throw PolicyError.invalid }
        for value in paths {
            guard value.hasPrefix("/"), value.utf8.count <= 4096, !value.contains("\0"),
                  URL(fileURLWithPath: value).standardizedFileURL.path == value else { throw PolicyError.invalid }
        }
        if let root = bundleRoot {
            guard root.hasSuffix(".app"), executable.hasPrefix(root + "/Contents/"),
                  URL(fileURLWithPath: root).standardizedFileURL.path == root else { throw PolicyError.invalid }
        }
        if let name = bundleIdentifier {
            guard name.count <= 255, name.range(of: "^[A-Za-z0-9][A-Za-z0-9.-]*$", options: .regularExpression) != nil else { throw PolicyError.invalid }
        }
    }
    func matches(_ path: String) -> Bool {
        executable == path || aliases?.contains(path) == true || bundleRoot.map { path == $0 || path.hasPrefix($0 + "/") } == true
    }
    var binding: FilterTarget {
        return FilterTarget(id: id, service: service, executable: executable, bundleRoot: bundleRoot, allowed: false, keepRunning: false, aliases: aliases, bundleIdentifier: bundleIdentifier)
    }
}

enum PolicyError: Error { case invalid }
struct FilterPolicy: Codable {
    let format: Int
    let uid: UInt32
    let targets: [FilterTarget]
    var sequence: UInt64? = nil
    static func decode(_ data: Data, uid: UInt32) throws -> FilterPolicy {
        guard data.count <= 524288 else { throw PolicyError.invalid }
        let value = try JSONDecoder().decode(FilterPolicy.self, from: data)
        guard value.format == 1, value.uid == uid, value.targets.count <= 256,
              Set(value.targets.map(\.id)).count == value.targets.count else { throw PolicyError.invalid }
        for target in value.targets { try target.validate() }
        for left in value.targets {
            for right in value.targets where left.service != right.service {
                if left.paths.contains(where: { right.matches($0) }) || right.paths.contains(where: { left.matches($0) }) { throw PolicyError.invalid }
            }
        }
        return value
    }
}

enum FilterDecision { case unmanaged, allow, block }
private struct RuleIndex {
    var exact: [String: Bool] = [:]
    var roots: [String: Bool] = [:]
    var identifiers: Set<String> = []
    init(_ targets: [FilterTarget]) {
        for target in targets {
            for value in target.paths { exact[value] = (exact[value] ?? true) && target.allowed }
            if let root = target.bundleRoot { roots[root] = (roots[root] ?? true) && target.allowed }
            if let identifier = target.bundleIdentifier { identifiers.insert(identifier) }
        }
    }
}
final class PolicyStore {
    private let lock = NSLock()
    private var rules: [UInt32: RuleIndex] = [:]
    private var deadlines: [UInt32: TimeInterval] = [:]
    private var peers: [UInt32: UUID] = [:]
    private var revisions: [UInt32: UInt64] = [:]

    func loadBindings(_ data: Data?) throws {
        guard let data = data else { return }
        guard data.count <= 1048576 else { throw PolicyError.invalid }
        let entries = try JSONDecoder().decode([String: [FilterTarget]].self, from: data)
        var result: [UInt32: RuleIndex] = [:]
        for (key, values) in entries {
            guard let uid = UInt32(key), values.count <= 256 else { throw PolicyError.invalid }
            let encoded = try JSONEncoder().encode(FilterPolicy(format: 1, uid: uid, targets: values))
            let valid = try FilterPolicy.decode(encoded, uid: uid).targets.map(\.binding)
            if !valid.isEmpty { result[uid] = RuleIndex(valid) }
        }
        lock.lock(); defer { lock.unlock() }
        rules = result; deadlines = [:]; peers = [:]; revisions = [:]
    }
    func update(_ data: Data, uid: UInt32, peer: UUID, now: TimeInterval) throws {
        let policy = try FilterPolicy.decode(data, uid: uid)
        guard let sequence = policy.sequence, sequence > 0 else { throw PolicyError.invalid }
        let index = RuleIndex(policy.targets)
        lock.lock(); defer { lock.unlock() }
        if peers[uid] == peer, sequence <= (revisions[uid] ?? 0) { throw PolicyError.invalid }
        rules[uid] = policy.targets.isEmpty ? nil : index
        peers[uid] = peer; revisions[uid] = sequence; deadlines[uid] = now + 3.5
    }
    func disconnected(uid: UInt32, peer: UUID) {
        lock.lock(); defer { lock.unlock() }
        if peers[uid] == peer { deadlines[uid] = nil; peers[uid] = nil; revisions[uid] = nil }
    }
    func decision(path: String, uid: UInt32, now: TimeInterval) -> FilterDecision {
        lock.lock(); defer { lock.unlock() }
        guard let rule = rules[uid] else { return .unmanaged }
        let exact = rule.exact[path]
        var found = exact != nil, allowed = exact ?? true
        for (root, permit) in rule.roots where path == root || path.hasPrefix(root + "/") { found = true; allowed = allowed && permit }
        if !found { return .unmanaged }
        return allowed && deadlines[uid].map { now <= $0 } == true ? .allow : .block
    }
    func unidentifiedApp(identifier: String?, uid: UInt32) -> FilterDecision {
        lock.lock(); defer { lock.unlock() }
        guard let identifier = identifier, let rule = rules[uid] else { return .unmanaged }
        return rule.identifiers.contains(where: { identifier == $0 || identifier.hasSuffix("." + $0) }) ? .block : .unmanaged
    }
}
