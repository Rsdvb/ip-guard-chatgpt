import Foundation
import NetworkExtension
import SystemExtensions

private let extensionID = "com.ip-guard.desktop.filter"
private var cleanup: (() -> Void)?
private func emit(_ phase: String, _ message: String, sequence: UInt64? = nil, running: [RunningProcess]? = nil) {
    var value: [String: Any] = ["phase": phase, "message": message]
    if let sequence = sequence { value["sequence"] = sequence }
    if let running = running, let data = try? JSONEncoder().encode(running), let records = try? JSONSerialization.jsonObject(with: data) { value["running"] = records }
    if let data = try? JSONSerialization.data(withJSONObject: value) {
        FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
    }
}
private func fail(_ message: String) -> Never { let revoke = cleanup; cleanup = nil; revoke?(); emit("error", message); exit(1) }

final class FilterControl: NSObject, OSSystemExtensionRequestDelegate {
    let manager = NEFilterManager.shared()
    let team: String
    var policy: FilterPolicy?
    var connection: NSXPCConnection?
    private var previousTargets: [FilterTarget]?
    private lazy var monitor = ProcessMonitor()
    init(team: String) { self.team = team }

    private func load(_ body: @escaping () -> Void) {
        manager.loadFromPreferences { error in
            if let error = error { fail(error.localizedDescription) }
            if let id = self.manager.providerConfiguration?.filterDataProviderBundleIdentifier, id != extensionID {
                fail("过滤配置属于其他扩展，未覆盖它")
            }
            body()
        }
    }
    func status() {
        load {
            guard self.manager.isEnabled else { emit("disabled", "系统网络过滤未启用"); exit(0) }
            self.connect { proxy in proxy.ping { ok in emit(ok ? "enabled" : "error", ok ? "系统过滤器已响应" : "过滤器未响应"); exit(ok ? 0 : 1) } }
        }
    }
    func enable(policy: FilterPolicy) {
        do {
            let resolved = try monitor.resolved(policy)
            guard !monitor.hasRunning(resolved) else { fail("请先退出已登记应用，再启用系统防护；已有连接需要重新建立") }
            self.policy = resolved
        } catch { fail("无法确认受保护程序路径：\(error)") }
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
        request.delegate = self; OSSystemExtensionManager.shared.submitRequest(request)
    }
    func disable() {
        load {
            self.manager.isEnabled = false
            self.manager.saveToPreferences { error in
                if let error = error { fail(error.localizedDescription) }
                emit("disabled", "系统网络过滤已关闭；网页和受控启动策略继续独立运行"); exit(0)
            }
        }
    }
    private func bindings(_ policy: FilterPolicy) throws -> Data {
        var values: [String: [FilterTarget]] = [:]
        if let old = manager.providerConfiguration?.vendorConfiguration?["IPGuardBindings"] as? Data {
            values = try JSONDecoder().decode([String: [FilterTarget]].self, from: old)
        }
        values[String(policy.uid)] = policy.targets.map(\.binding)
        return try JSONEncoder().encode(values)
    }
    private func configured() {
        guard let policy = policy else { fail("缺少初始拒绝规则") }
        load {
            do {
                let configuration = self.manager.providerConfiguration ?? NEFilterProviderConfiguration()
                let saved = try self.bindings(policy)
                configuration.filterSockets = true; configuration.filterBrowsers = false
                configuration.filterDataProviderBundleIdentifier = extensionID
                configuration.vendorConfiguration = ["IPGuardBindings": saved]
                self.manager.providerConfiguration = configuration
                self.manager.localizedDescription = "IP Guard · Claude / ChatGPT"
                self.manager.isEnabled = true
                self.manager.saveToPreferences { error in
                    if let error = error { fail(error.localizedDescription) }
                    emit("enabled", "系统过滤配置已启用，正在建立策略通道"); exit(0)
                }
            } catch { fail(error.localizedDescription) }
        }
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { emit("approval", "请在 macOS 系统设置中允许 IP Guard 系统扩展，然后允许网络过滤") }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if result == .completed { configured() }
        else { emit("approval", "系统要求重新启动后完成扩展安装，重启后再启用过滤"); exit(0) }
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { fail(error.localizedDescription) }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension old: OSSystemExtensionProperties, withExtension new: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }

    private func connect(_ callback: @escaping (IPGuardPolicyChannel) -> Void) {
        let channel = NSXPCConnection(machServiceName: team + ".com.ip-guard.desktop.policy", options: [])
        channel.remoteObjectInterface = NSXPCInterface(with: IPGuardPolicyChannel.self)
        channel.invalidationHandler = { fail("系统过滤策略通道已断开，受保护应用网络将保持拒绝") }
        connection = channel; channel.resume()
        guard let proxy = channel.remoteObjectProxyWithErrorHandler({ error in fail(error.localizedDescription) }) as? IPGuardPolicyChannel else { fail("无法建立系统过滤策略通道") }
        callback(proxy)
    }
    func stop(policy: FilterPolicy) {
        do {
            let resolved = try monitor.resolved(policy)
            _ = try monitor.enforce(resolved, force: true)
            guard !monitor.hasRunning(resolved) else { fail("仍有受保护程序未结束，请稍后重试") }
            emit("enabled", "已结束所选服务的已登记程序"); exit(0)
        } catch { fail("停止所选程序失败：\(error)") }
    }
    func stream() {
        load {
          if let data = self.manager.providerConfiguration?.vendorConfiguration?["IPGuardBindings"] as? Data,
             let bindings = try? JSONDecoder().decode([String: [FilterTarget]].self, from: data) {
              self.monitor.seed(bindings[String(getuid())] ?? [])
          }
          self.connect { proxy in
            cleanup = { self.monitor.revokeAll() }
            DispatchQueue.global().async {
                var sequence: UInt64 = 0
                while let line = readLine() {
                    guard line.utf8.count <= 524288, let data = line.data(using: .utf8) else { fail("策略格式错误") }
                    do {
                        let policy = try self.monitor.resolved(FilterPolicy.decode(data, uid: getuid()))
                        guard let revision = policy.sequence, revision > sequence else { fail("策略版本无效或重复") }
                        sequence = revision
                        let wait = DispatchSemaphore(value: 0)
                        var accepted = false
                        proxy.update(try JSONEncoder().encode(policy)) { ok in accepted = ok; wait.signal() }
                        guard wait.wait(timeout: .now() + 3) == .success, accepted else { fail("系统过滤器拒绝或未确认本次策略") }
                        let running = try self.monitor.enforce(policy)
                        let binding = policy.targets.map(\.binding)
                        if binding != self.previousTargets {
                            let saved = DispatchSemaphore(value: 0)
                            DispatchQueue.main.async {
                                self.load {
                                    do {
                                        guard let configuration = self.manager.providerConfiguration else { fail("系统过滤配置不存在") }
                                        configuration.vendorConfiguration = ["IPGuardBindings": try self.bindings(policy)]
                                        self.manager.providerConfiguration = configuration
                                        self.manager.saveToPreferences { error in
                                            if let error = error { fail(error.localizedDescription) }
                                            saved.signal()
                                        }
                                    } catch { fail(error.localizedDescription) }
                                }
                            }
                            guard saved.wait(timeout: .now() + 5) == .success else { fail("持久化系统过滤规则超时") }
                            self.previousTargets = binding
                        }
                        emit("enabled", "系统过滤器已确认当前用户的独立 IP 策略", sequence: revision, running: running)
                    } catch { fail(error.localizedDescription) }
                }
                self.monitor.revokeAll(); cleanup = nil; self.connection?.invalidationHandler = nil
                self.connection?.invalidate(); exit(0)
            }
          }
        }
    }
}

@main enum ControlMain {
    static var retained: FilterControl?
    static func main() {
        let executable = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        let containingApp = executable.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        guard let team = codeTeam(), team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
              containingApp.pathExtension == "app", Bundle(url: containingApp)?.bundleIdentifier == "com.ip-guard.desktop" else {
            emit("unavailable", "请先在 Mac 上完成 Developer ID 签名、配置描述文件并安装到 Applications"); exit(0)
        }
        let control = FilterControl(team: team); retained = control
        let operation = CommandLine.arguments.dropFirst().first ?? "status"
        if operation == "status" { control.status() }
        else if operation == "disable" { control.disable() }
        else if operation == "stream" { control.stream() }
        else if operation == "enable" || operation == "stop" {
            guard let line = readLine(), line.utf8.count <= 524288, let data = line.data(using: .utf8) else { fail("缺少初始过滤规则") }
            do {
                let policy = try FilterPolicy.decode(data, uid: getuid())
                if operation == "stop" { control.stop(policy: policy) } else { control.enable(policy: policy) }
            }
            catch { fail(error.localizedDescription) }
        } else { fail("未知过滤操作") }
        DispatchQueue.main.asyncAfter(deadline: .now() + (operation == "enable" ? 120 : 15)) {
            if operation != "stream" { fail("系统过滤操作等待超时，请检查系统授权后重试") }
        }
        dispatchMain()
    }
}
