import Foundation
import AppKit
import Darwin
import Security

struct RunningProcess: Codable { let id: String; let service: String; let pid: Int32 }
private struct ProcessRecord {
    let pid: Int32
    let path: String
    let seconds: UInt64
    let micros: UInt64
}
enum ProcessMonitorError: Error { case unsafeTarget, unableToStop }

final class ProcessMonitor {
    private let operationLock = NSRecursiveLock()
    private var records: [ProcessRecord] = []
    private var previous: [String: FilterTarget] = [:]
    private var lastScan: TimeInterval = 0
    private var lastDenied: Set<String> = []
    private var observer: NSObjectProtocol?
    private let dirtyLock = NSLock()
    private var dirty = true
    private var identifierCache: [String: (String, String?)] = [:]
    private(set) var latest: FilterPolicy?
    init() {
        observer = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: .main) { [weak self] _ in
            guard let self = self else { return }
            self.dirtyLock.lock(); self.dirty = true; self.dirtyLock.unlock()
        }
    }
    deinit { if let observer = observer { NSWorkspace.shared.notificationCenter.removeObserver(observer) } }
    private func inspect(_ pid: Int32, previous: ProcessRecord? = nil) -> ProcessRecord? {
        guard pid > 1, pid != getpid() else { return nil }
        var info = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) == Int32(MemoryLayout<proc_bsdinfo>.size), info.pbi_uid == getuid() else { return nil }
        // sys/proc.h marks an exited process awaiting its parent as SZOMB (5).
        guard info.pbi_status != 5 else { return nil }
        // Darwin exposes MAXPATHLEN to Swift, but not the proc-info expression macro.
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let count = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        if count > 0 { return ProcessRecord(pid: pid, path: URL(fileURLWithPath:String(cString: buffer)).standardizedFileURL.path, seconds: info.pbi_start_tvsec, micros: info.pbi_start_tvusec) }
        if let old = previous, old.seconds == info.pbi_start_tvsec, old.micros == info.pbi_start_tvusec { return old }
        return nil
    }
    private func refresh(force: Bool) {
        dirtyLock.lock(); let changed = dirty; dirty = false; dirtyLock.unlock()
        if !force && !changed && continuousNow() - lastScan < 5 { return }
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { records = []; return }
        var ids = [Int32](repeating: 0, count: Int(count) + 512)
        let actual = ids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        let prior = Dictionary(uniqueKeysWithValues: records.map { ($0.pid, $0) })
        records = ids.prefix(max(0, min(Int(actual), ids.count))).compactMap { inspect($0, previous: prior[$0]) }
        lastScan = continuousNow()
    }
    private func canonical(_ file: String) -> String {
        let fd = open(file, O_RDONLY | O_CLOEXEC)
        if fd >= 0 {
            defer { close(fd) }
            var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            if fcntl(fd, F_GETPATH, &buffer) == 0 { return URL(fileURLWithPath:String(cString: buffer)).standardizedFileURL.path }
        }
        return URL(fileURLWithPath: file).resolvingSymlinksInPath().path
    }
    private func identifier(_ file: String, root: String?) -> String? {
        var info = stat()
        let stamp = stat(file, &info) == 0 ? "\(info.st_ino):\(info.st_mtimespec.tv_sec):\(info.st_mtimespec.tv_nsec)" : "missing"
        if let cached = identifierCache[file], cached.0 == stamp { return cached.1 }
        func remember(_ value: String?) -> String? {
            let valid = value.flatMap { name in name.count <= 255 && name.range(of: "^[A-Za-z0-9][A-Za-z0-9.-]*$", options: .regularExpression) != nil ? name : nil }
            identifierCache[file] = (stamp, valid); return valid
        }
        if let root = root, let value = Bundle(path: root)?.bundleIdentifier { return remember(value) }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: file) as CFURL, [], &code) == errSecSuccess, let code = code else { return remember(nil) }
        var data: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &data) == errSecSuccess, let values = data as? [String: Any] else { return remember(nil) }
        return remember(values[kSecCodeInfoIdentifier as String] as? String)
    }
    func resolved(_ policy: FilterPolicy) throws -> FilterPolicy {
        operationLock.lock(); defer { operationLock.unlock() }
        refresh(force: false)
        let ids = Set(policy.targets.map(\.id)); previous = previous.filter { ids.contains($0.key) }
        var targets: [FilterTarget] = []
        let own = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let ownExecutable = canonical(CommandLine.arguments[0])
        for target in policy.targets {
            let file = canonical(target.executable)
            let root = file.range(of: ".app/Contents/").map { String(file[..<$0.lowerBound]) + ".app" }
            guard file != ownExecutable, root == nil || own.pathExtension != "app" || root != own.path else { throw ProcessMonitorError.unsafeTarget }
            if root == nil, ["bash", "sh", "zsh", "fish", "sudo", "su", "osascript", "launchctl", "node", "python", "python3", "ruby", "perl"].contains(URL(fileURLWithPath: file).lastPathComponent) { throw ProcessMonitorError.unsafeTarget }
            var aliases = target.aliases ?? []
            if let old = previous[target.id] {
                if old.executable != file { refresh(force: true); aliases.append(old.executable) }
                aliases += old.aliases ?? []
            }
            aliases = Array(Set(aliases)).filter { value in value != file && records.contains { $0.path == value } }.sorted()
            guard aliases.count <= 16 else { throw PolicyError.invalid }
            let value = FilterTarget(id: target.id, service: target.service, executable: file, bundleRoot: root, allowed: target.allowed, keepRunning: target.keepRunning, aliases: aliases.isEmpty ? nil : aliases, bundleIdentifier: identifier(file, root: root))
            targets.append(value); previous[target.id] = value
        }
        let value = FilterPolicy(format: 1, uid: policy.uid, targets: targets, sequence: policy.sequence)
        return try FilterPolicy.decode(JSONEncoder().encode(value), uid: policy.uid)
    }
    func running(_ policy: FilterPolicy, force: Bool = false) -> [RunningProcess] {
        operationLock.lock(); defer { operationLock.unlock() }
        refresh(force: force)
        return policy.targets.flatMap { target in
            records.compactMap { record -> RunningProcess? in
                guard target.matches(record.path), let live = inspect(record.pid, previous: record), live.seconds == record.seconds, live.micros == record.micros else { return nil }
                return RunningProcess(id: target.id, service: target.service, pid: record.pid)
            }
        }.sorted { $0.id == $1.id ? $0.pid < $1.pid : $0.id < $1.id }
    }
    func hasRunning(_ policy: FilterPolicy) -> Bool { !running(policy, force: true).isEmpty }
    private func signal(_ record: ProcessRecord, value: Int32) throws {
        guard let current = inspect(record.pid, previous: record), current.seconds == record.seconds, current.micros == record.micros, current.path == record.path else { return }
        if kill(record.pid, value) != 0 && errno != ESRCH { throw ProcessMonitorError.unableToStop }
    }
    func enforce(_ policy: FilterPolicy, force: Bool = false) throws -> [RunningProcess] {
        operationLock.lock(); defer { operationLock.unlock() }
        latest = policy
        let denied = Set(policy.targets.filter { !($0.keepRunning ?? $0.allowed) }.map(\.id))
        refresh(force: force || denied != lastDenied); lastDenied = denied
        let targets = policy.targets.filter { denied.contains($0.id) }
        let victims = records.filter { record in targets.contains { $0.matches(record.path) } }
        for record in victims { try signal(record, value: SIGTERM) }
        if !victims.isEmpty {
            let deadline = continuousNow() + 0.8
            while continuousNow() < deadline && victims.contains(where: { record in
                guard let current = inspect(record.pid, previous: record) else { return false }
                return current.seconds == record.seconds && current.micros == record.micros && current.path == record.path
            }) { Thread.sleep(forTimeInterval: 0.05) }
            for record in victims { try signal(record, value: SIGKILL) }
            refresh(force: true)
        }
        return running(policy)
    }
    func revokeAll() {
        operationLock.lock(); defer { operationLock.unlock() }
        guard let policy = latest else { return }
        let targets = policy.targets.map { target -> FilterTarget in var value = target; value.keepRunning = false; return value }
        _ = try? enforce(FilterPolicy(format: 1, uid: policy.uid, targets: targets), force: true)
    }
    func seed(_ targets: [FilterTarget]) {
        operationLock.lock(); defer { operationLock.unlock() }
        for target in targets { previous[target.id] = target }
    }
}
