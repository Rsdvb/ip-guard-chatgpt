namespace IpGuard {
    public sealed class LaunchAttempt {
        public string id,phase="starting",message="正在请求启动";
        public bool Complete(string detail) {
            if(phase!="starting") return false;
            phase="started"; message=detail; return true;
        }
        public bool Fail(string detail) {
            if(phase!="starting") return false;
            phase="failed"; message=detail; return true;
        }
    }
}
