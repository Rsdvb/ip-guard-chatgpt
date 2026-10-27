using System;
using System.Collections.Generic;
using System.IO;

namespace IpGuard {
    public static class NativePolicyTests {
        static void Assert(bool condition,string message) { if(!condition) throw new Exception(message); }
        public static int Main() {
            bool migrate;
            Config legacy=Data.Parse("{\"settings\":{\"expectedIp\":\"8.8.8.8\",\"intervalSeconds\":2},\"apps\":[],\"rulesLocked\":true,\"ipSource\":\"claude-ai\"}",out migrate);
            Assert(legacy.settings.service=="claude" && legacy.rulesLocked && migrate,"Legacy settings must preserve Claude scope");
            foreach(string service in new[] { "claude","chatgpt","both" }) {
                Config current=Data.Parse("{\"settings\":{\"expectedIp\":\"8.8.8.8\",\"intervalSeconds\":2,\"service\":\""+service+"\"},\"apps\":[],\"rulesLocked\":true,\"ipSource\":\"claude-ai\"}",out migrate);
                Assert(current.settings.service==service && !migrate,"Current scope must survive reload");
                ClaudeProbe probe=null;
                probe=new ClaudeProbe(message=>{
                    var request=Data.Json().Deserialize<Dictionary<string,object>>(Data.Json().Serialize(message));
                    Assert(request["service"] as string==service,"Native probe must send selected service");
                    probe.Receive(new Dictionary<string,object> {
                        {"action","probe-result"},{"id",request["id"]},
                        {"data",new { ip="8.8.8.8",error="",checkedAt=DateTimeOffset.UtcNow.ToString("o"),adapter="test" }}
                    });
                });
                Assert(probe.Read(service,null).ip=="8.8.8.8","Native probe must accept a matching fresh result");
                probe.Stop();
            }
            bool rejected=false;
            try { Data.Parse("{\"settings\":{\"service\":\"invalid\"},\"apps\":[],\"rulesLocked\":false,\"ipSource\":\"claude-ai\"}",out migrate); }
            catch(Exception) { rejected=true; }
            Assert(rejected,"Unknown service must be rejected even when unlocked");
            Console.WriteLine("PASS: legacy migration, three persisted service modes, native service forwarding and invalid service rejection.");
            return 0;
        }
    }
}
