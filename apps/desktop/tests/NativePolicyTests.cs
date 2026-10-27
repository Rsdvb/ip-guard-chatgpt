using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
namespace IpGuard {
    public static class NativePolicyTests {
        static void Assert(bool condition,string message) { if(!condition) throw new Exception(message); }
        static void Reject(string source) { bool rejected=false; try { bool migrate; Data.Parse(source,out migrate); } catch(Exception) { rejected=true; } Assert(rejected,"Invalid persisted config must fail closed"); }
        public static int Main() {
            bool migrate;
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
