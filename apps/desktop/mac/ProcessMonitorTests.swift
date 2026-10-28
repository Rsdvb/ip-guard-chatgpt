import Foundation
import Darwin

@main enum ProcessMonitorTests {
    static func main() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("ipg-process-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        var children: [Process] = []
        defer {
            for child in children { if child.isRunning { child.terminate() }; child.waitUntilExit() }
            try? FileManager.default.removeItem(at: root)
        }
        for name in ["claude-fixture", "chatgpt-fixture", "unrelated-fixture"] {
            let file = root.appendingPathComponent(name)
            try FileManager.default.copyItem(atPath: "/bin/sleep", toPath: file.path)
            let child = Process(); child.executableURL = file; child.arguments = ["120"]
            try child.run(); children.append(child)
        }
        let claude = FilterTarget(id: UUID().uuidString, service: "claude", executable: root.appendingPathComponent("claude-fixture").path, bundleRoot: nil, allowed: true, keepRunning: true)
        let gpt = FilterTarget(id: UUID().uuidString, service: "chatgpt", executable: root.appendingPathComponent("chatgpt-fixture").path, bundleRoot: nil, allowed: false, keepRunning: true)
        let monitor = ProcessMonitor()
        var policy = try monitor.resolved(FilterPolicy(format: 1, uid: getuid(), targets: [claude, gpt], sequence: 1))
        precondition(monitor.running(policy, force: true).count == 2, "Registered native processes must be discovered by path and UID")
        _ = try monitor.enforce(policy, force: true)
        precondition(children.allSatisfy(\.isRunning), "Unavailable-IP opt-out must retain both registered processes")
        var targets = policy.targets; targets[1].keepRunning = false
        policy = FilterPolicy(format:1,uid:getuid(),targets:targets,sequence:2)
        let remaining = try monitor.enforce(policy, force: true)
        precondition(!remaining.contains { $0.pid == children[1].processIdentifier }, "Terminated processes must not remain in system running state")
        children[1].waitUntilExit()
        precondition(children[0].isRunning && children[2].isRunning, "ChatGPT termination must not affect Claude or unrelated processes")
        monitor.revokeAll(); children[0].waitUntilExit()
        precondition(children[2].isRunning, "Guardian loss must retain unrelated processes")
        print("PASS macOS native processes: path and UID discovery, unavailable-IP opt-out, independent termination and guardian-loss cleanup")
    }
}
