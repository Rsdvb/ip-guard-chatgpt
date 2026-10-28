using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
namespace IpGuard {
    public sealed class ServiceRuntime {
        public readonly object gate=new object();
        public readonly System.Threading.AutoResetEvent wake=new System.Threading.AutoResetEvent(false);
        public readonly List<Session> sessions=new List<Session>();
        public bool healthy,pendingBlock,checking,unverified;
        public string currentIp="",reason="请先锁定该服务允许的公网 IPv4",checkedAt="",adapter="";
        public int epoch,checkRequested;
        public long lastVerified;
        public DateTime nextCheck=DateTime.MinValue;
        public Session[] Revoke(string why,bool preserveIp) {
            healthy=false; unverified=false; reason=why; epoch++; pendingBlock=true;
            if(!preserveIp) currentIp="";
            Session[] active=sessions.Where(s=>!s.stopped).ToArray();
            foreach(Session session in active) session.stopped=true;
            return active;
        }
        public Session[] ProbeFailed(Rule rule,string why) {
            if(rule.stopOnProbeFailure || !rule.enabled || !rule.rulesLocked) return Revoke(why,false);
            healthy=false; unverified=true; reason=why; currentIp="";
            return new Session[0];
        }
        public bool CanContinue(Rule rule) { return rule.enabled && rule.rulesLocked && (Fresh(rule.settings.intervalSeconds) || (!rule.stopOnProbeFailure && unverified)); }
        public bool Fresh(int interval) { return healthy && lastVerified!=0 && Stopwatch.GetTimestamp()-lastVerified<=Stopwatch.Frequency*(interval+8); }
    }
}
