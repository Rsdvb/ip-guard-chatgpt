using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace IpGuard {
    public sealed class Session {
        public string appId;
        public string name;
        public IntPtr job;
        public int epoch;
        public volatile bool stopped;
        public bool started;
    }
    public sealed class Guard {
        readonly object state = new object(), actions = new object(), output = new object();
        readonly Dictionary<string,ServiceRuntime> runtimes = new Dictionary<string,ServiceRuntime> { { "claude",new ServiceRuntime() }, { "chatgpt",new ServiceRuntime() } };
        readonly Dictionary<string,LaunchAttempt> launches=new Dictionary<string,LaunchAttempt>();
        readonly Dictionary<string,string> targetErrors=new Dictionary<string,string>();
        readonly List<object> logs = new List<object>();
        readonly Config config;
        readonly WifiWatch wifi;
        readonly ServiceProbe probe;
        readonly BlockingCollection<Dictionary<string,object>> commands=new BlockingCollection<Dictionary<string,object>>();
        AdapterInfo[] adapters=new AdapterInfo[0];
        AdapterInfo watchedAdapter=new AdapterInfo { id="",name="正在检测网卡",exists=false };
        volatile bool quit;
        readonly AutoResetEvent networkWake=new AutoResetEvent(false);
        string topology="",detection="";
        static string ServiceName(string service) { return service=="claude" ? "Claude" : "ChatGPT"; }
        IEnumerable<Session> AllSessions { get { return runtimes.Values.SelectMany(r=>r.sessions); } }
        public Guard() { config = Data.Load(); wifi = new WifiWatch(why => Observe(why, true)); probe=new ServiceProbe(Emit); RefreshAdapters(); }
        void Emit(object message) { lock(output) { Console.WriteLine(Data.Json().Serialize(message)); Console.Out.Flush(); } }
        void Log(string level, string message) {
            object entry = new { time = DateTimeOffset.Now.ToString("o"), level = level, message = message };
            lock(state) { logs.Insert(0, entry); if(logs.Count > 200) logs.RemoveAt(logs.Count-1); }
            try {
                Directory.CreateDirectory(Data.DirectoryPath);
                string file = Path.Combine(Data.DirectoryPath, "events.jsonl");
                lock(output) {
                    if (File.Exists(file) && new FileInfo(file).Length > 1048576) { File.Copy(file, file + ".1", true); File.Delete(file); }
                    File.AppendAllText(file, Data.Json().Serialize(entry) + Environment.NewLine, new UTF8Encoding(false));
                }
            } catch (Exception e) { Console.Error.WriteLine("日志写入失败: " + e.Message); }
        }
        object ServiceSnapshot(string service) {
            ServiceRuntime r=runtimes[service]; Rule rule=config.services[service];
            return new { ready=r.healthy,checking=r.checking,currentIp=r.currentIp,adapter=r.adapter,lastChecked=r.checkedAt,reason=r.reason,rulesLocked=rule.rulesLocked,enabled=rule.enabled,settings=rule.settings,stopOnProbeFailure=rule.stopOnProbeFailure,unverified=r.unverified };
        }
        public object Snapshot() {
            lock(state) return new {
                online=true,admin=SystemPolicy.Admin,nativeVersion=BuildInfo.Version,
                services=new { claude=ServiceSnapshot("claude"),chatgpt=ServiceSnapshot("chatgpt") },
                networkAdapters=adapters,watchedAdapter=watchedAdapter,networkAdapterId=config.networkAdapterId,
                detection=detection,launches=launches.Values.ToArray(),running=AllSessions.Where(s=>!s.stopped && s.started).Select(s=>s.appId).Distinct().ToArray(),
                autostart=config.autostart,apps=config.apps.Select(t=>new { t.id,t.service,t.name,t.path,t.arguments,t.enabled,protectionError=targetErrors.ContainsKey(t.id) ? targetErrors[t.id] : "" }).ToArray(),logs=logs.ToArray()
            };
        }
        void Publish() { Emit(new { type = "snapshot", data = Snapshot() }); }
        void Observe(string message, bool networkChanged = false) {
            bool changed;
            lock(state) {
                changed = detection != message; detection = message;
                if(networkChanged) foreach(ServiceRuntime r in runtimes.Values) { Interlocked.Exchange(ref r.checkRequested,1); r.wake.Set(); }
            }
            if(changed) { if(!networkChanged) Log("info",message); Publish(); }
        }
        void Trip(string service,string why,bool preserveIp=false) {
            ServiceRuntime r=runtimes[service]; bool changed;
            lock(state) {
                changed=r.healthy || r.reason!=why || r.sessions.Any(s=>!s.stopped);
                foreach(Session session in r.Revoke(why,preserveIp)) Win32.TerminateJobObject(session.job,1);
            }
            if(changed) { Log("warning",ServiceName(service)+" · "+why); Publish(); }
        }
        void TripAll(string why) { foreach(string service in runtimes.Keys) Trip(service,why); }
        void BlockPending() {
            foreach(string service in runtimes.Keys) {
                ServiceRuntime r=runtimes[service]; bool block;
                lock(state) { block=r.pendingBlock; r.pendingBlock=false; }
                if(!block || !SystemPolicy.Admin) continue;
                Target[] targets;
                lock(state) targets=config.apps.Where(t=>t.service==service && t.enabled && !targetErrors.ContainsKey(t.id) && (!r.CanContinue(config.services[service]) || !r.sessions.Any(s=>s.appId==t.id && !s.stopped))).ToArray();
                foreach(Target target in targets) try { SystemPolicy.Block(target,true); }
                catch(Exception e) { lock(state) r.pendingBlock=true; Log("error","封锁失败 · "+target.name+" · "+e.Message); }
            }
        }
        bool Check(string service,Action<ProbeProgress> progress=null) {
            ServiceRuntime r=runtimes[service];
            lock(r.gate) return CheckLocked(service,progress);
        }
        bool CheckLocked(string service,Action<ProbeProgress> progress=null) {
            ServiceRuntime r=runtimes[service]; Rule rule=config.services[service];
            Interlocked.Exchange(ref r.checkRequested,0);
            int startEpoch; lock(state) { startEpoch=r.epoch; r.checking=true; }
            Publish();
            try {
                if(!rule.enabled || !rule.rulesLocked) {
                    lock(state) { r.healthy=false; r.reason=rule.rulesLocked ? "该服务已暂停，连接保持阻断" : "请先锁定该服务允许的公网 IPv4"; }
                    return false;
                }
                ServiceProbeResult result=probe.Read(service,progress); string ip=result.ip;
                lock(state) { r.currentIp=ip; r.checkedAt=result.checkedAt; r.adapter=result.adapter ?? ""; }
                if(progress!=null) progress(new ProbeProgress("match","锁定地址",ip==rule.settings.expectedIp ? "ok" : "error",ip==rule.settings.expectedIp ? "IPv4 完全匹配" : "IPv4 与该服务锁定地址不同"));
                if(ip!=rule.settings.expectedIp) {
                    Trip(service,"出口 IPv4 不符 · 实测 "+ip+" · 锁定 "+rule.settings.expectedIp+" · 仅阻断该服务",true);
                    return false;
                }
                lock(state) {
                    if(startEpoch!=r.epoch) return false;
                    r.healthy=true; r.unverified=false; r.reason=""; r.lastVerified=Stopwatch.GetTimestamp();
                }
                return true;
            } catch(Exception error) {
                lock(state) r.checkedAt=DateTimeOffset.Now.ToString("o");
                ProbeFailed(service,"出口检测失败（未确认 IP 变化） · "+error.GetBaseException().Message);
                return false;
            } finally {
                lock(state) r.checking=false;
                r.nextCheck=Interlocked.Exchange(ref r.checkRequested,0)==1 ? DateTime.MinValue : DateTime.UtcNow.AddSeconds(rule.settings.intervalSeconds);
                Publish();
            }
        }
        void ProbeFailed(string service,string why) {
            ServiceRuntime r=runtimes[service]; Rule rule=config.services[service];
            string message=why+(rule.stopOnProbeFailure ? " · 已结束该服务受保护程序" : " · 按设置保留已运行程序，出口未确认");
            bool changed;
            lock(state) {
                changed=r.healthy || r.reason!=message;
                foreach(Session session in r.ProbeFailed(rule,message)) Win32.TerminateJobObject(session.job,1);
            }
            if(changed) { Log("warning",ServiceName(service)+" · "+message); Publish(); }
        }
        Target Find(string id) {
            Target t = config.apps.SingleOrDefault(a => a.id == id);
            if(t == null) throw new Exception("找不到该程序。"); return t;
        }
        static void RequireClosed(Target t) {
            foreach(Process p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(t.path))) using(p) {
                try { if(String.Equals(p.MainModule.FileName, t.path, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("请先关闭 " + t.name + " 的所有进程。"); }
                catch(System.ComponentModel.Win32Exception) { throw new Exception("请先关闭同名进程，再启用防护。"); }
            }
        }
        void StopTarget(string id) {
            lock(state) foreach(Session s in AllSessions.Where(s => s.appId == id)) { s.stopped = true; Win32.TerminateJobObject(s.job, 1); }
        }
        void RefreshTargets(bool initializing=false) {
            lock(actions) foreach(Target target in config.apps.ToArray()) RefreshTarget(target,initializing);
        }
        void RefreshTarget(Target target,bool initializing=false) {
            try {
                string resolved=PackagePolicy.ResolveInstalledPath(target.path);
                Target next=new Target { id=target.id,service=target.service,name=target.name,path=resolved,arguments=target.arguments,enabled=target.enabled };
                Data.Validate(next,true);
                if(config.apps.Any(other=>other.id!=target.id && String.Equals(other.path,next.path,StringComparison.OrdinalIgnoreCase))) throw new Exception("更新后的入口与另一条程序记录重复，请移除重复项。");
                bool moved=!String.Equals(target.path,next.path,StringComparison.OrdinalIgnoreCase),retry;
                lock(state) retry=targetErrors.ContainsKey(target.id);
                if(!initializing && !moved && !retry) return;
                if(target.enabled) {
                    if(moved) RequireClosed(next);
                    StopTarget(target.id);
                    if(moved) { SystemPolicy.Block(target,true); SystemPolicy.Unintercept(target); SystemPolicy.RemoveFirewall(target); }
                }
                if(moved) {
                    lock(state) target.path=next.path;
                }
                if(moved || retry) Data.Save(config);
                if(target.enabled) { SystemPolicy.Block(target,true); SystemPolicy.Intercept(target); }
                lock(state) targetErrors.Remove(target.id);
                if(moved) Log("info",target.name+" · 已识别应用升级并更新程序入口，原 IP 规则保持不变");
                else if(retry) Log("info",target.name+" · 程序入口已恢复");
                if(moved || retry) Publish();
            } catch(Exception error) {
                string message=error.GetBaseException().Message; bool changed;
                lock(state) { string prior; changed=!targetErrors.TryGetValue(target.id,out prior) || prior!=message; targetErrors[target.id]=message; }
                if(changed) { StopTarget(target.id); Log("warning",target.name+" · 程序防护未就绪 · "+message); Publish(); }
            }
        }
        void Protect(Target t, bool enabled) {
            if(enabled && !config.services[t.service].rulesLocked) throw new Exception("请先锁定允许的公网 IPv4，再启用程序防护。");
            SystemPolicy.RequireAdmin(); StopTarget(t.id);
            if(enabled) {
                RefreshTarget(t);
                lock(state) if(targetErrors.ContainsKey(t.id)) throw new Exception(targetErrors[t.id]);
                Data.Validate(config.services[t.service].settings); Data.Validate(t, true); RequireClosed(t); SystemPolicy.FirewallHealthy();
                SystemPolicy.Block(t, true);
                try { SystemPolicy.Intercept(t); t.enabled = true; Data.Save(config); }
                catch { SystemPolicy.Unintercept(t); SystemPolicy.RemoveFirewall(t); t.enabled = false; throw; }
            } else {
                SystemPolicy.Unintercept(t); SystemPolicy.RemoveFirewall(t); t.enabled = false; Data.Save(config);
                lock(state) targetErrors.Remove(t.id);
            }
            Log("info", t.name + (enabled ? " · 已接管启动" : " · 已解除防护"));
        }
        object Command(Dictionary<string,object> input) {
            string action = input["action"] as string;
            lock(actions) {
                if(action == "status") return Snapshot();
                if(action == "check") { string key=input["service"] as string; Data.ValidateService(key); Check(key); return Snapshot(); }
                SystemPolicy.RequireAdmin();
                if(action=="lock" || action=="unlock" || action=="service:enable" || action=="failure-policy") {
                    string key=input["service"] as string; Data.ValidateService(key);
                    ServiceRuntime r=runtimes[key];
                    lock(r.gate) {
                        Rule prior=config.services[key]; Rule next;
                        if(action=="failure-policy") {
                            next=new Rule { settings=prior.settings,rulesLocked=prior.rulesLocked,enabled=prior.enabled,stopOnProbeFailure=(bool)input["stopOnProbeFailure"] };
                            var policies=new Dictionary<string,Rule>(config.services); policies[key]=next; Save(policies,config.apps);
                            Log("info",ServiceName(key)+(next.stopOnProbeFailure ? " · 无法获取 IP 时自动结束程序：开" : " · 无法获取 IP 时自动结束程序：关"));
                            if(next.stopOnProbeFailure && r.unverified) CheckLocked(key);
                            BlockPending(); return Snapshot();
                        }
                        if(action=="lock") {
                            if(prior.rulesLocked) throw new Exception("请先取消该服务的锁定再修改。");
                            Settings settings=Data.Json().Deserialize<Settings>(Data.Json().Serialize(input["settings"])); Data.Validate(settings);
                            next=new Rule { settings=settings,rulesLocked=true,enabled=true,stopOnProbeFailure=prior.stopOnProbeFailure };
                        } else if(action=="unlock") next=new Rule { settings=prior.settings,rulesLocked=false,enabled=false,stopOnProbeFailure=prior.stopOnProbeFailure };
                        else {
                            bool enabled=(bool)input["enabled"];
                            if(enabled && !prior.rulesLocked) throw new Exception("请先锁定该服务允许的公网 IPv4。");
                            next=new Rule { settings=prior.settings,rulesLocked=prior.rulesLocked,enabled=enabled,stopOnProbeFailure=prior.stopOnProbeFailure };
                        }
                        var services=new Dictionary<string,Rule>(config.services); services[key]=next;
                        Save(services,config.apps);
                        Trip(key,action=="unlock" ? "IP 已取消锁定，仅该服务已阻断" : next.enabled ? "正在校验该服务锁定的公网 IPv4" : "该服务已暂停，连接保持阻断");
                        if(next.enabled) CheckLocked(key);
                        BlockPending();
                        Log("info",ServiceName(key)+" · "+(next.enabled ? "已启用独立规则" : "已停止独立规则"));
                    }
                } else if(action == "adapter:set") {
                    string id=input["adapterId"] as string;
                    AdapterInfo chosen=id=="" ? null : NetworkProbe.Adapters().SingleOrDefault(n=>n.id==id);
                    if(id==null || (id!="" && chosen==null)) throw new Exception("所选网卡当前不存在，请重新选择。");
                    lock(state) { config.networkAdapterId=id; config.networkAdapterName=chosen==null ? "" : chosen.name; }
                    Data.Save(config); RefreshAdapters();
                } else if(action == "browser:register") {
                    BrowserHost.Register();
                } else if(action == "add") {
                    Target t = Data.Json().Deserialize<Target>(Data.Json().Serialize(input["app"])); Data.Validate(t, true);
                    if(config.apps.Count >= 30) throw new Exception("最多添加 30 个程序。");
                    if(config.apps.Any(a => a.id == t.id || String.Equals(a.path,t.path,StringComparison.OrdinalIgnoreCase))) throw new Exception("该程序已在列表中。");
                    t.enabled = false; lock(state) config.apps.Add(t); Data.Save(config); Log("info", t.name + " · 已添加");
                } else if(action == "autostart") {
                    bool enabled = (bool)input["enabled"]; SystemPolicy.Autostart(enabled, input["executable"] as string);
                    lock(state) config.autostart = enabled; Data.Save(config); Log("info", enabled ? "已开启登录后启动" : "已关闭登录后启动");
                } else {
                    Target t = Find(input["targetId"] as string);
                    if(action == "protect") Protect(t, (bool)input["enabled"]);
                    else if(action == "edit") {
                        Target changed=new Target { id=t.id,path=t.path,service=input["service"] as string,enabled=t.enabled,name=input["name"] as string,arguments=input["arguments"] as string };
                        Data.Validate(changed,false);
                        if(changed.service!=t.service && (t.enabled || AllSessions.Any(session=>session.appId==t.id && !session.stopped))) throw new Exception("请先解除该程序防护，再修改归属服务。");
                        List<Target> next=config.apps.Select(a=>a.id==t.id ? changed : a).ToList();
                        Save(config.services,next);
                        Log("info",changed.name+" · 启动配置已更新");
                    }
                    else if(action == "remove") { if(t.enabled) Protect(t, false); lock(state) { config.apps.Remove(t); targetErrors.Remove(t.id); } Data.Save(config); }
                    else if(action == "stop") { StopTarget(t.id); SystemPolicy.Block(t,true); Log("info", t.name + " · 已停止并封锁"); }
                    else if(action == "start") {
                        RefreshTarget(t);
                        lock(state) if(targetErrors.ContainsKey(t.id)) throw new Exception(targetErrors[t.id]);
                        if(!config.services[t.service].rulesLocked || !config.services[t.service].enabled) throw new Exception("请先锁定并开启该程序所属服务。");
                        if(!t.enabled) throw new Exception("请先启用该程序的防护。");
                        Data.Validate(t, true);
                        LaunchAttempt prior;
                        lock(state) {
                            if(launches.TryGetValue(t.id,out prior) && prior.phase=="starting") throw new Exception("该程序正在启动，请等待当前结果。");
                            if(AllSessions.Any(session=>session.appId==t.id && !session.stopped)) throw new Exception("该程序已有受保护实例。");
                            var attempt=new LaunchAttempt { id=t.id }; launches[t.id]=attempt;
                            Background(()=>WatchLaunch(t,attempt));
                            Background(()=> {
                                try {
                                    if(PackagePolicy.Find(t.path)!=null) PackagePolicy.Activate(t);
                                    else Process.Start(new ProcessStartInfo(t.path,t.arguments) { UseShellExecute=true,WorkingDirectory=Path.GetDirectoryName(t.path) });
                                } catch(Exception error) { LaunchFailed(attempt,t.name+" · "+error.GetBaseException().Message); }
                            });
                        }
                    } else throw new Exception("未知操作。");
                }
                return Snapshot();
            }
        }
        void LaunchFailed(LaunchAttempt attempt,string message) {
            bool changed; lock(state) changed=attempt.Fail(message);
            if(changed) { Log("warning",message); Publish(); }
        }
        void WatchLaunch(Target target,LaunchAttempt attempt) {
            try { WatchLaunchResult(target,attempt); }
            catch(Exception error) { LaunchFailed(attempt,target.name+" · 启动确认失败 · "+error.GetBaseException().Message); }
        }
        void WatchLaunchResult(Target target,LaunchAttempt attempt) {
            long started=Stopwatch.GetTimestamp(); bool console=TerminalProcess.IsConsole(target.path);
            while(!quit && Stopwatch.GetTimestamp()-started<Stopwatch.Frequency*30) {
                Session[] candidates;
                lock(state) {
                    if(attempt.phase!="starting") return;
                    candidates=AllSessions.Where(session=>session.appId==target.id && session.started && !session.stopped).ToArray();
                }
                bool opened=false,foreground=false;
                foreach(Session session in candidates) {
                    IntPtr handle=IntPtr.Zero;
                    lock(state) {
                        if(!session.stopped) Win32.DuplicateHandle(Win32.GetCurrentProcess(),session.job,Win32.GetCurrentProcess(),out handle,0,false,2);
                    }
                    if(handle==IntPtr.Zero) continue;
                    try { if(console || WindowActivation.ShowProtectedWindow(handle,out foreground)) { opened=true; break; } }
                    finally { Win32.CloseHandle(handle); }
                }
                if(opened) {
                    lock(state) attempt.Complete(console ? "受保护进程已启动" : foreground ? "应用窗口已打开" : "窗口已出现，Windows 未允许切换前台，可点击任务栏打开");
                    Publish(); return;
                }
                Thread.Sleep(200);
            }
            if(!quit) LaunchFailed(attempt,target.name+" · 未确认应用窗口出现。请查看启动校验窗口或从原快捷方式打开；IP Guard 不会绕过校验。");
        }
        void Save(Dictionary<string,Rule> services,List<Target> apps) {
            Data.Save(new Config { services=services,apps=apps,autostart=config.autostart,networkAdapterId=config.networkAdapterId,networkAdapterName=config.networkAdapterName });
            lock(state) { config.services=services; config.apps=apps; }
        }
        void Loop(string service) {
            ServiceRuntime r=runtimes[service];
            while(!quit) {
                try {
                    if(Monitor.TryEnter(r.gate)) {
                        try { Rule rule=config.services[service]; if(rule.enabled && rule.rulesLocked && (DateTime.UtcNow>=r.nextCheck || Interlocked.CompareExchange(ref r.checkRequested,0,0)==1)) CheckLocked(service); }
                        finally { Monitor.Exit(r.gate); }
                    }
                    if(Monitor.TryEnter(actions)) { try { BlockPending(); } finally { Monitor.Exit(actions); } }
                } catch(Exception e) { Observe(ServiceName(service)+" · 守护状态检测异常 · "+e.GetBaseException().Message); }
                r.wake.WaitOne(500);
            }
        }
        void WatchNetwork() {
            DateTime nextTargets=DateTime.UtcNow.AddMinutes(1);
            while(!quit) {
                try {
                    if(SystemPolicy.Admin && DateTime.UtcNow>=nextTargets) { RefreshTargets(); nextTargets=DateTime.UtcNow.AddMinutes(1); }
                    RefreshAdapters();
                    string now = NetworkProbe.Fingerprint(); string prior;
                    lock(state) { prior=topology; topology=now; }
                    if(prior!="" && now!=prior) Observe("本机 IPv4 或路由配置更新，正在复核服务出口",true);
                    wifi.Ensure();
                } catch(Exception e) { Observe("网络状态检测异常 · " + e.Message); }
                networkWake.WaitOne(60000);
                if(!quit) Thread.Sleep(250);
            }
        }
        void RefreshAdapters() {
            try {
                AdapterInfo[] current=NetworkProbe.Adapters(); string id,name;
                lock(state) { id=config.networkAdapterId; name=config.networkAdapterName; }
                AdapterInfo selected=NetworkProbe.Watched(current,id,name);
                lock(state) { adapters=current; watchedAdapter=selected; }
            } catch(NetworkInformationException e) {
                lock(state) watchedAdapter=new AdapterInfo { id=config.networkAdapterId,name="网卡检测失败",error=e.Message };
            }
        }
        PipeSecurity PipeAcl() {
            PipeSecurity acl = new PipeSecurity(); acl.SetAccessRuleProtection(true,false);
            foreach(SecurityIdentifier sid in new[] { WindowsIdentity.GetCurrent().User, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null), new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null) }) acl.AddAccessRule(new PipeAccessRule(sid,PipeAccessRights.FullControl,AccessControlType.Allow));
            return acl;
        }
        void Listen() {
            while(!quit) {
                NamedPipeServerStream pipe = null;
                try {
                    pipe = new NamedPipeServerStream(SystemPolicy.PipeName,PipeDirection.InOut,64,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,4096,4096,PipeAcl());
                    pipe.WaitForConnection(); NamedPipeServerStream connected = pipe;
                    Background(() => GateSession(connected));
                } catch(Exception e) { if(pipe != null) pipe.Dispose(); if(!quit) { Observe("启动门卫异常 · " + e.Message); Thread.Sleep(1000); } }
            }
        }
        static void Background(Action action) { Thread thread = new Thread(() => action()); thread.IsBackground = true; thread.Start(); }
        bool CanInherit(NamedPipeServerStream pipe,string appId) {
            uint pid;
            Win32.Check(Win32.GetNamedPipeClientProcessId(pipe.SafePipeHandle,out pid),"无法核对启动来源");
            IntPtr process=Win32.OpenProcess(0x1000,false,pid);
            if(process==IntPtr.Zero) return false;
            try {
                lock(state) {
                    Target target=Find(appId); ServiceRuntime r=runtimes[target.service]; Rule rule=config.services[target.service];
                    if(targetErrors.ContainsKey(target.id)) return false;
                    if(!r.CanContinue(rule)) return false;
                    foreach(Session session in r.sessions.Where(s=>s.appId==appId && !s.stopped && s.epoch==r.epoch)) {
                        bool inside;
                        Win32.Check(Win32.IsProcessInJob(process,session.job,out inside),"无法核对受保护进程树");
                        if(inside) return true;
                    }
                    return false;
                }
            } finally { Win32.CloseHandle(process); }
        }
        void GateSession(NamedPipeServerStream pipe) {
            Session session = null; Target target = null; ServiceRuntime r=null; Rule rule=null; LaunchAttempt launchAttempt=null;
            try {
            using(pipe) using(StreamReader reader = new StreamReader(pipe,new UTF8Encoding(false),false,1024,true)) using(StreamWriter writer = new PipeWriter(pipe)) {
                try {
                    Task<string> read = Task.Run(() => reader.ReadLine());
                    if(!read.Wait(5000)) throw new Exception("启动请求超时。");
                    string line = read.Result;
                    if(line == null || line.Length > 8192) throw new Exception("启动请求无效。");
                    var request = Data.Json().Deserialize<Dictionary<string,object>>(line);
                    if(request.ContainsKey("action") && request["action"] as string=="scope") {
                        writer.WriteLine(Data.Json().Serialize(new { inherit=CanInherit(pipe,request["id"] as string) }));
                        return;
                    }
                    bool inherited=request.ContainsKey("inherit") && request["inherit"] is bool && (bool)request["inherit"];
                    lock(actions) {
                        target = Find(request["id"] as string);
                        lock(state) if(targetErrors.ContainsKey(target.id)) throw new Exception(targetErrors[target.id]);
                        lock(state) launches.TryGetValue(target.id,out launchAttempt);
                        r=runtimes[target.service]; rule=config.services[target.service];
                        lock(r.gate) {
                        if(!target.enabled || !String.Equals(target.path,request["path"] as string,StringComparison.OrdinalIgnoreCase)) throw new Exception("该程序未启用启动防护。");
                        writer.WriteLine(Data.Json().Serialize(new { type="context", name=target.name, expectedIp=rule.settings.expectedIp }));
                        if(!rule.rulesLocked || !rule.enabled) throw new Exception("请先锁定并开启该服务的防护。");
                        if(PackagePolicy.Find(target.path)!=null) {
                            if(!request.ContainsKey("package") || !(bool)request["package"]) throw new Exception("请通过 Desktop 原快捷方式或 IP Guard 的启动按钮打开安装包。");
                            Win32.ProcessInfo existing=PackagePolicy.OpenTarget(target,Convert.ToUInt32(request["pid"]),Convert.ToUInt32(request["tid"]));
                            Win32.CloseHandle(existing.thread); Win32.CloseHandle(existing.process);
                        }
                        bool disconnected=false;
                        Action<ProbeProgress> progress = item => {
                            if(disconnected) return;
                            try { writer.WriteLine(Data.Json().Serialize(new { type="progress", data=item })); }
                            catch(IOException) { disconnected=true; }
                        };
                        progress(new ProbeProgress("security","系统防护","running","检查防火墙与 IP 锁定"));
                        SystemPolicy.FirewallHealthy();
                        progress(new ProbeProgress("security","系统防护","ok","锁定与防火墙已就绪"));
                        if(inherited) {
                            if(!CanInherit(pipe,target.id)) throw new Exception("原启动许可已失效，子进程启动已阻断。");
                        } else if(!CheckLocked(target.service,progress)) throw new Exception(r.reason);
                        if(disconnected) throw new IOException("启动校验窗口已关闭。");
                        string name = "Local\\IPGuard-" + Guid.NewGuid().ToString("D");
                        lock(state) {
                            if(!(inherited ? r.CanContinue(rule) : r.healthy)) throw new Exception(r.reason);
                            session = new Session { appId=target.id, name=name, job=Win32.NewJob(name), epoch=r.epoch };
                            r.sessions.Add(session);
                        }
                        writer.WriteLine(Data.Json().Serialize(new { allow=true, job=name, currentIp=r.currentIp, expectedIp=rule.settings.expectedIp }));
                        Task<string> started = Task.Run(() => reader.ReadLine());
                        if(!started.Wait(8000) || started.Result != "started") throw new Exception("目标进程未完成启动准备。");
                        SystemPolicy.Block(target,false);
                        lock(state) { if(session.stopped || session.epoch != r.epoch || !r.CanContinue(rule)) throw new Exception("启动许可已撤销。"); writer.WriteLine("run"); }
                        }
                    }
                    if(!inherited) Log("info", target.name + " · 校验通过，等待应用恢复"); Publish();
                    Task<string> alive = Task.Run(() => reader.ReadLine());
                    while(!quit && !session.stopped) {
                        if(alive.IsCompleted) {
                            if(alive.Result!="resumed") break;
                            lock(state) session.started=true; Publish();
                            alive=Task.Run(()=>reader.ReadLine());
                        }
                        bool stale;
                        lock(state) {
                            rule=config.services[target.service];
                            if(session.epoch != r.epoch || !rule.enabled || !rule.rulesLocked) break;
                            stale = !r.Fresh(rule.settings.intervalSeconds) && !r.unverified;
                            if(!stale && !r.CanContinue(rule)) break;
                            if(!stale) writer.WriteLine("lease");
                        }
                        if(stale) { ProbeFailed(target.service,"该服务出口检测结果已过期"); if(!r.CanContinue(rule)) break; writer.WriteLine("lease"); }
                        Thread.Sleep(400);
                    }
                } catch(Exception e) {
                    if(target!=null && launchAttempt!=null) LaunchFailed(launchAttempt,target.name+" · "+e.GetBaseException().Message);
                    Log("warning", (target == null ? "启动拦截" : target.name) + " · " + e.GetBaseException().Message);
                    try { writer.WriteLine(Data.Json().Serialize(new { allow=false, currentIp=r==null ? "" : r.currentIp, expectedIp=rule==null ? "" : rule.settings.expectedIp, error=e.GetBaseException().Message, code=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Code : "" })); } catch(IOException) { }
                } finally {
                    if(session != null) lock(state) { session.stopped=true; Win32.TerminateJobObject(session.job,1); Win32.CloseHandle(session.job); r.sessions.Remove(session); r.pendingBlock=true; }
                    Publish();
                }
            }
            } catch(IOException e) { Log("info", "启动连接已关闭 · " + e.Message); }
        }
        public void Run() {
            try { BrowserHost.Register(true); } catch(Exception error) { Log("error","浏览器连接注册失败 · "+error.Message); }
            if(config.apps.Any(t => t.enabled) && SystemPolicy.Admin) {
                TripAll("守护程序已启动，等待重新校验");
            }
            if(SystemPolicy.Admin) { RefreshTargets(true); BlockPending(); }
            NetworkChange.NetworkAddressChanged += NetworkChanged;
            NetworkChange.NetworkAvailabilityChanged += AvailabilityChanged;
            SystemEvents.PowerModeChanged += PowerChanged;
            if(SystemPolicy.Admin) Background(Listen);
            Background(Dispatch); Background(()=>Loop("claude")); Background(()=>Loop("chatgpt")); Background(WatchNetwork); Publish();
            try {
                string line;
                while((line=Console.ReadLine()) != null) {
                    string id = "";
                    try {
                        if(line.Length > 32768) throw new Exception("操作请求过长。");
                        var input = Data.Json().Deserialize<Dictionary<string,object>>(line); id = input["id"] as string;
                        if((string)input["action"] == "shutdown") { Emit(new { id=id, ok=true, data=Snapshot() }); break; }
                        string action=input["action"] as string;
                        if(action=="probe-result" || action=="probe-progress") probe.Receive(input);
                        else commands.Add(input);
                    } catch(Exception e) { Emit(new { id=id, ok=false, error=e.GetBaseException().Message, code=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Code : "", help=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Help : "" }); }
                }
            } finally {
                quit=true; probe.Stop(); commands.CompleteAdding(); TripAll("守护程序已退出，受保护程序已结束");
                lock(actions) BlockPending();
                NetworkChange.NetworkAddressChanged -= NetworkChanged; NetworkChange.NetworkAvailabilityChanged -= AvailabilityChanged; SystemEvents.PowerModeChanged -= PowerChanged;
                wifi.Dispose();
            }
        }
        void Dispatch() {
            foreach(Dictionary<string,object> input in commands.GetConsumingEnumerable()) {
                if(quit) return;
                string id=input["id"] as string;
                try { object result=Command(input); Emit(new { id=id,ok=true,data=result }); Publish(); }
                catch(Exception e) { Emit(new { id=id,ok=false,error=e.GetBaseException().Message,code=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Code : "",help=e.GetBaseException() is FirewallDisabledException ? FirewallDisabledException.Help : "" }); }
            }
        }
        void NetworkChanged(object sender,EventArgs e) { RequestNetworkCheck(); }
        void AvailabilityChanged(object sender,NetworkAvailabilityEventArgs e) { RequestNetworkCheck(); }
        void RequestNetworkCheck() { networkWake.Set(); }
        void PowerChanged(object sender,PowerModeChangedEventArgs e) { Observe("系统电源状态改变",true); }
    }
}
