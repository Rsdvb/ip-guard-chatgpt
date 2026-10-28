using System;
using System.Diagnostics;
using System.IO;

namespace IpGuard {
    public static class DesktopBootstrap {
        public static string Executable(string nativeExecutable) {
            if(!Path.IsPathRooted(nativeExecutable) || !String.Equals(Path.GetFileName(nativeExecutable),"IpGuard.Native.exe",StringComparison.OrdinalIgnoreCase)) throw new Exception("原生组件路径无效。");
            DirectoryInfo version=Directory.GetParent(nativeExecutable);
            if(version==null || version.Name!=BuildInfo.Version || version.Parent==null || !String.Equals(version.Parent.Name,"native",StringComparison.OrdinalIgnoreCase) || version.Parent.Parent==null || !String.Equals(version.Parent.Parent.Name,"resources",StringComparison.OrdinalIgnoreCase) || version.Parent.Parent.Parent==null) throw new Exception("请使用完整安装的 IP Guard。");
            return Path.Combine(version.Parent.Parent.Parent.FullName,"IP Guard.exe");
        }
        public static void Elevate(bool background) {
            string executable=Executable(SystemPolicy.Exe);
            if(!File.Exists(executable)) throw new Exception("桌面程序缺失，请重新安装 IP Guard。");
            var start=new ProcessStartInfo(executable,background ? "--background" : "") { UseShellExecute=true,Verb="runas",WorkingDirectory=Path.GetDirectoryName(executable) };
            Process launched=Process.Start(start);
            if(launched!=null) launched.Dispose();
        }
    }
}
