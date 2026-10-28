using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Runtime.InteropServices;
using System.Windows.Forms;
namespace IpGuard {
    public static class NativePolicyTests {
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool CreateRestrictedToken(IntPtr original,uint flags,uint disable,IntPtr groups,uint delete,IntPtr privileges,uint restrict,IntPtr sids,out IntPtr token);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSidToSid(string value,out IntPtr sid);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool SetTokenInformation(IntPtr token,int kind,ref TokenLabel label,int length);
        [DllImport("advapi32.dll")] static extern int GetLengthSid(IntPtr sid);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
        [StructLayout(LayoutKind.Sequential)] struct TokenLabel { public IntPtr sid; public uint attributes; }
        static int MediumHost(string origin) {
            IntPtr original=IntPtr.Zero,restricted=IntPtr.Zero,sid=IntPtr.Zero;
            try {
                Win32.Check(OpenProcessToken(Win32.GetCurrentProcess(),0xf01ff,out original));
                Win32.Check(CreateRestrictedToken(original,4,0,IntPtr.Zero,0,IntPtr.Zero,0,IntPtr.Zero,out restricted));
                Win32.Check(ConvertStringSidToSid("S-1-16-8192",out sid));
                var label=new TokenLabel { sid=sid,attributes=0x20 };
                Win32.Check(SetTokenInformation(restricted,25,ref label,Marshal.SizeOf(label)+GetLengthSid(sid)));
                using(System.Security.Principal.WindowsImpersonationContext context=System.Security.Principal.WindowsIdentity.Impersonate(restricted)) {
                    Assert(!SystemPolicy.Admin,"Browser test must use an ordinary, non-administrator token");
                    return BrowserHost.Run(origin);
                }
            } finally { if(sid!=IntPtr.Zero) LocalFree(sid); if(restricted!=IntPtr.Zero) Win32.CloseHandle(restricted); if(original!=IntPtr.Zero) Win32.CloseHandle(original); }
        }
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
        static void Assert(bool condition,string message) { if(!condition) throw new Exception(message); }
        static void Reject(string source) { bool rejected=false; try { bool migrate; Data.Parse(source,out migrate); } catch(Exception) { rejected=true; } Assert(rejected,"Invalid persisted config must fail closed"); }
        public static int Main(string[] args) {
            try { return Run(args); }
            catch(Exception error) { Console.Error.WriteLine("FAIL: "+error.Message); return 1; }
        }
        static int Run(string[] args) {
            if(args.Length==1 && args[0]=="--assert-released") {
                Config config=Data.Load();
                foreach(Target target in config.apps) {
                    foreach(var view in new[] { Microsoft.Win32.RegistryView.Registry64,Microsoft.Win32.RegistryView.Registry32 })
                        using(var root=Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine,view))
                        using(var key=root.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\"+Path.GetFileName(target.path)+"\\IPGuard_"+target.id)) Assert(key==null,"Explicit exit must remove the target's startup interception");
                    using(var marker=Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\IPGuard\PackageDebugging\"+target.id)) Assert(marker==null,"Explicit exit must remove owned package-debug registration");
                }
                dynamic firewall=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2",true));
                foreach(dynamic rule in firewall.Rules) Assert((string)rule.Grouping!=SystemPolicy.Owner,"Explicit exit must remove its firewall rules");
                Assert(File.Exists(Path.Combine(Data.DirectoryPath,"browser","released")),"Explicit exit must also release browser protection");
                Console.WriteLine("PASS: no owned startup hook, package-debug marker or firewall rule remains after explicit release"); return 0;
            }
            if(args.Length==2 && args[0]=="--medium-native-host") return MediumHost(args[1]);
            if(args.Length==2 && args[0]=="--hidden-window") {
                using(Form window=new Form { Text="IP Guard hidden-window fixture",Width=480,Height=320 }) {
                    window.Shown+=(sender,eventArgs)=>{window.Hide(); File.WriteAllText(args[1],window.Handle.ToInt64().ToString());};
                    using(var timer=new System.Windows.Forms.Timer { Interval=20000 }) { timer.Tick+=(sender,eventArgs)=>window.Close(); timer.Start(); Application.Run(window); }
                }
                return 0;
            }
            if(args.Length==3 && args[0]=="--resolve-upgraded-package") {
                string resolved=PackagePolicy.ResolveInstalledPath(args[1]);
                Assert(String.Equals(resolved,args[2],StringComparison.OrdinalIgnoreCase),"An upgraded app must resolve to the current user's registered package, preserving the executable entry");
                Assert(PackagePolicy.Find(resolved)!=null,"Resolved entry must retain a registered package identity");
                Console.WriteLine("PASS: upgraded package resolves to its registered executable."); return 0;
            }
            if(args.Length==2 && args[0]=="--inspect-package") {
                var package=PackagePolicy.Find(args[1]); Assert(package!=null,"Registered package must be found");
                Console.WriteLine(Data.Json().Serialize(new { package=package.fullName,appUserModelId=package.appUserModelId,isConsole=TerminalProcess.IsConsole(args[1]) })); return 0;
            }
            IntPtr emptyJob=Win32.NewJob("Local\\IPGuard-Test-"+Guid.NewGuid().ToString("D"));
            try { bool foreground; Assert(!WindowActivation.ShowProtectedWindow(emptyJob,out foreground) && !foreground,"An empty protected job must not select or focus unrelated windows"); }
            finally { Win32.CloseHandle(emptyJob); }
            string windowFile=Path.Combine(Path.GetTempPath(),"ipg-window-"+Guid.NewGuid().ToString("N"));
            IntPtr windowJob=Win32.NewJob("Local\\IPGuard-WindowTest-"+Guid.NewGuid().ToString("D"));
            try {
                using(Process fixture=Process.Start(new ProcessStartInfo(typeof(NativePolicyTests).Assembly.Location,"--hidden-window "+Data.Quote(windowFile)) { UseShellExecute=false })) {
                    Win32.Check(Win32.AssignProcessToJobObject(windowJob,fixture.Handle));
                    Stopwatch timeout=Stopwatch.StartNew(); while(!File.Exists(windowFile) && timeout.ElapsedMilliseconds<5000) Thread.Sleep(20);
                    Assert(File.Exists(windowFile),"Hidden application window must initialize");
                    IntPtr window=new IntPtr(Int64.Parse(File.ReadAllText(windowFile))); bool foreground;
                    Assert(!IsWindowVisible(window),"Fixture must reproduce a process running with a hidden main window");
                    Assert(WindowActivation.ShowProtectedWindow(windowJob,out foreground),"Managed start must restore the protected hidden main window instead of reporting a launch timeout");
                    timeout.Restart(); while(!IsWindowVisible(window) && timeout.ElapsedMilliseconds<3000) Thread.Sleep(20);
                    Assert(IsWindowVisible(window),"Managed start must actually make the hidden window visible");
                }
            } finally { Win32.TerminateJobObject(windowJob,0); Win32.CloseHandle(windowJob); File.Delete(windowFile); }
            var pendingLaunch=new LaunchAttempt { id="test" };
            Assert(pendingLaunch.phase=="starting" && pendingLaunch.Fail("activation denied") && !pendingLaunch.Complete("late success"),"Failed launch must be visible and cannot be overwritten by a late completion");
            var successfulLaunch=new LaunchAttempt(); Assert(successfulLaunch.Complete("visible window") && !successfulLaunch.Fail("late error"),"Successful launch must not be overwritten by a stale error");
            bool migrate;
            string desktopRoot=Path.Combine(Path.GetTempPath(),"IP Guard Bootstrap Test");
            string nativeQueryPath=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"native",BuildInfo.Version,"IpGuard.Native.exe");
            using(Process query=Process.Start(new ProcessStartInfo(nativeQueryPath,"admin-status") { UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true })) {
                Assert(query!=null,"Native privilege query must start");
                if(!query.WaitForExit(5000)) {query.Kill();Assert(false,"Native privilege query must not wait on the guardian mutex or display a dialog");}
                string output=query.StandardOutput.ReadToEnd();
                Assert(query.ExitCode==0,"Native privilege query must exit successfully");
                var metadata=Data.Json().Deserialize<Dictionary<string,object>>(output);
                Assert(metadata!=null && metadata.ContainsKey("admin") && metadata["admin"] is bool && (bool)metadata["admin"]==SystemPolicy.Admin,"Native privilege query must report the actual Windows token over JSON");
            }
            string bootstrapNative=Path.Combine(desktopRoot,"resources","native",BuildInfo.Version,"IpGuard.Native.exe");
            Assert(DesktopBootstrap.Executable(bootstrapNative)==Path.Combine(desktopRoot,"IP Guard.exe"),"Elevation must resolve only the installed sibling desktop executable");
            foreach(string invalid in new[] {"IpGuard.Native.exe",Path.Combine(desktopRoot,"resources","native","other-version","IpGuard.Native.exe"),Path.Combine(desktopRoot,"other","native",BuildInfo.Version,"IpGuard.Native.exe"),Path.Combine(desktopRoot,"resources","native",BuildInfo.Version,"Other.exe")}) {
                bool rejected=false;try{DesktopBootstrap.Executable(invalid);}catch(Exception){rejected=true;}Assert(rejected,"Invalid elevation layout must not select an arbitrary executable");
            }
            Config legacy=Data.Parse("{\"settings\":{\"expectedIp\":\"8.8.8.8\",\"intervalSeconds\":2},\"apps\":[],\"rulesLocked\":true,\"ipSource\":\"claude-ai\"}",out migrate);
            Assert(migrate && legacy.services["claude"].rulesLocked && legacy.services["claude"].enabled,"Legacy Claude permission must be preserved");
            Assert(!legacy.services["chatgpt"].rulesLocked && !legacy.services["chatgpt"].enabled,"Legacy Claude rule cannot authorize ChatGPT");
            Config current=new Config();
            current.services["claude"]=new Rule { settings=new Settings { expectedIp="8.8.8.8",intervalSeconds=2 },rulesLocked=true,enabled=true };
            current.services["chatgpt"]=new Rule { settings=new Settings { expectedIp="1.1.1.1",intervalSeconds=5 },rulesLocked=true,enabled=false };
            Config loaded=Data.Parse(Data.Json().Serialize(current),out migrate);
            Assert(!migrate && loaded.services["claude"].settings.expectedIp=="8.8.8.8" && loaded.services["chatgpt"].settings.expectedIp=="1.1.1.1","Independent IPs must survive reload");
            Assert(loaded.services["claude"].enabled && !loaded.services["chatgpt"].enabled && loaded.services["chatgpt"].rulesLocked,"Pause must preserve that service lock without pausing the other");
            foreach(string selected in new[] { "claude","chatgpt","both" }) {
                string old="{\"settings\":{\"service\":\""+selected+"\",\"expectedIp\":\"8.8.8.8\",\"intervalSeconds\":2},\"rulesLocked\":true,\"apps\":[{\"id\":\"00000000-0000-4000-8000-000000000001\",\"name\":\"renamed app\",\"path\":\"C:\\\\ChatGPT.exe\",\"enabled\":true}]}";
                Config imported=Data.Parse(old,out migrate);
                Assert(migrate && imported.apps[0].service=="chatgpt","Installed ChatGPT must bind to its own rule even when old global service was Claude");
                Assert(imported.services["claude"].rulesLocked==(selected!="chatgpt") && imported.services["chatgpt"].rulesLocked==(selected!="claude"),"Migrate only previously selected permissions");
            }
            Reject("{\"format\":2,\"services\":null,\"apps\":[]}");
            Reject("{\"settings\":{\"service\":\"invalid\"},\"apps\":[]}");
            var claude=new ServiceRuntime { healthy=true,lastVerified=Stopwatch.GetTimestamp(),currentIp="8.8.8.8" };
            var chatgpt=new ServiceRuntime { healthy=true,lastVerified=Stopwatch.GetTimestamp(),currentIp="1.1.1.1" };
            var claudeSession=new Session { appId="claude",epoch=claude.epoch };
            var gptSession=new Session { appId="gpt",epoch=chatgpt.epoch };
            claude.sessions.Add(claudeSession); chatgpt.sessions.Add(gptSession);
            Session[] revoked=chatgpt.Revoke("ChatGPT mismatch",true);
            Assert(revoked.Length==1 && revoked[0]==gptSession && gptSession.stopped && !chatgpt.Fresh(2),"Mismatch must revoke only affected service leases");
            Assert(!claudeSession.stopped && claude.Fresh(2) && claude.epoch==0 && !claude.pendingBlock,"Other service's process, freshness, epoch and firewall state must remain unchanged");
            claude.Revoke("Paused",false);
            Assert(claudeSession.stopped && chatgpt.currentIp=="1.1.1.1","Stopping Claude must not erase ChatGPT's diagnostic result");
            Assert(new Rule().stopOnProbeFailure,"Existing protection must keep ending apps on unavailable IP by default");
            var deployed=Data.Parse("{\"format\":2,\"services\":{\"claude\":{\"settings\":{\"expectedIp\":\"8.8.8.8\",\"intervalSeconds\":2},\"rulesLocked\":true,\"enabled\":true},\"chatgpt\":{\"settings\":{\"expectedIp\":\"1.1.1.1\",\"intervalSeconds\":2},\"rulesLocked\":true,\"enabled\":true}},\"apps\":[]}",out migrate);
            Assert(deployed.services["claude"].stopOnProbeFailure && deployed.services["chatgpt"].stopOnProbeFailure,"0.11 persisted configs with no preference must keep their existing strict behavior");
            loaded.services["chatgpt"].stopOnProbeFailure=false;
            var reloaded=Data.Parse(Data.Json().Serialize(loaded),out migrate);
            Assert(!reloaded.services["chatgpt"].stopOnProbeFailure && reloaded.services["claude"].stopOnProbeFailure,"Failure policy must persist independently");
            var retained=new ServiceRuntime { healthy=true,lastVerified=Stopwatch.GetTimestamp(),currentIp="1.1.1.1" };
            var retainedSession=new Session { appId="gpt",epoch=retained.epoch }; retained.sessions.Add(retainedSession);
            var relaxed=new Rule { enabled=true,rulesLocked=true,stopOnProbeFailure=false };
            var terminated=retained.ProbeFailed(relaxed,"probe timeout");
            Assert(terminated.Length==0 && !retainedSession.stopped && retained.unverified && !retained.healthy && retained.epoch==0,"Opt out must retain existing processes without claiming verified IP");
            Assert(retained.CanContinue(relaxed),"Existing leases can continue only under the opted out policy");
            Assert(!retained.CanContinue(new Rule { enabled=true,rulesLocked=true }),"Strict mode must reject unavailable leases");
            Assert(!retained.CanContinue(new Rule { enabled=false,rulesLocked=true,stopOnProbeFailure=false }),"Paused service cannot retain leases");
            retained.Revoke("confirmed mismatch",true);
            Assert(retainedSession.stopped && !retained.CanContinue(relaxed),"Confirmed mismatch always revokes even after opt out");
            var strictRuntime=new ServiceRuntime { healthy=true };strictRuntime.sessions.Add(new Session());
            Assert(strictRuntime.ProbeFailed(new Rule(),"timeout").Length==1,"Default failure policy must terminate affected sessions");
            // Only the remote trace service is simulated. The native correlation, validation and parallel wait implementation run unchanged.
            var claudeWaiting=new ManualResetEventSlim(false);
            var releaseClaude=new ManualResetEventSlim(false);
            ServiceProbe probe=null;
            probe=new ServiceProbe(message=> {
                var request=Data.Json().Deserialize<Dictionary<string,object>>(Data.Json().Serialize(message));
                string service=request["service"] as string;
                ThreadPool.QueueUserWorkItem(_=> {
                    if(service=="claude") { claudeWaiting.Set(); releaseClaude.Wait(5000); }
                    probe.Receive(new Dictionary<string,object> { {"action","probe-result"},{"id",request["id"]},{"data",new { ip=service=="claude" ? "8.8.8.8" : "1.1.1.1",error="",checkedAt=DateTimeOffset.UtcNow.ToString("o"),adapter="external-test" }} });
                });
            });
            var slow=System.Threading.Tasks.Task.Run(()=>probe.Read("claude",null));
            Assert(claudeWaiting.Wait(5000),"Claude external request must be in flight");
            try {
                var fast=System.Threading.Tasks.Task.Run(()=>probe.Read("chatgpt",null));
                Assert(fast.Wait(3000) && fast.Result.ip=="1.1.1.1" && !slow.IsCompleted,"Slow Claude probe must not block or contaminate ChatGPT");
            } finally { releaseClaude.Set(); }
            Assert(slow.Result.ip=="8.8.8.8","Native results must remain correlated to their service"); probe.Stop();
            claudeWaiting.Dispose(); releaseClaude.Dispose();
            Console.WriteLine("PASS: persisted migration, distinct IPs, independent pause, scoped revocation and concurrent native probes."); return 0;
        }
    }
}
