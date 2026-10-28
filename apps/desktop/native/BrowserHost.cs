using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace IpGuard {
    public static class BrowserHost {
        static object Offline(string reason) { return new { phase="offline",currentIp="",expectedIp="",checkedAt="",reason=reason }; }
        const string Host="com.ipguard.browser";
        static string Manifest { get { return Path.Combine(Data.DirectoryPath,"browser",Host+".json"); } }
        static string Released { get { return Path.Combine(Data.DirectoryPath,"browser","released"); } }
        public static void SetReleased(bool released) {
            if(!released) { if(File.Exists(Released)) File.Delete(Released); return; }
            Directory.CreateDirectory(Path.GetDirectoryName(Released));
            File.WriteAllText(Released,BuildInfo.Version,new UTF8Encoding(false));
        }
        static string[] Browsers { get { return new[] { @"Software\Google\Chrome\NativeMessagingHosts\", @"Software\Microsoft\Edge\NativeMessagingHosts\" }; } }
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string value,uint revision,out IntPtr descriptor,IntPtr size);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,out bool present,out IntPtr acl,out bool defaulted);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetSecurityDescriptorSacl(IntPtr descriptor,out bool present,out IntPtr acl,out bool defaulted);
        [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(IntPtr handle,int kind,uint information,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
        public static void SecurePipe(string name) {
            SystemPolicy.RequireAdmin();
            using(var pipe=new NamedPipeClientStream(".",name,PipeAccessRights.ReadWrite|PipeAccessRights.ChangePermissions|PipeAccessRights.TakeOwnership,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification,HandleInheritability.None)) {
                pipe.Connect(2000);
                IntPtr descriptor;
                Win32.Check(ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;"+SystemPolicy.Sid+")S:(ML;;NW;;;ME)",1,out descriptor,IntPtr.Zero));
                try {
                    bool present,defaulted; IntPtr dacl,sacl;
                    Win32.Check(GetSecurityDescriptorDacl(descriptor,out present,out dacl,out defaulted));
                    Win32.Check(GetSecurityDescriptorSacl(descriptor,out present,out sacl,out defaulted));
                    uint result=SetSecurityInfo(pipe.SafePipeHandle.DangerousGetHandle(),1,0x80000014,IntPtr.Zero,IntPtr.Zero,dacl,sacl);
                    if(result!=0) throw new System.ComponentModel.Win32Exception((int)result,"浏览器管道权限设置失败");
                } finally { LocalFree(descriptor); }
            }
        }
        public static void Register(bool refreshOnly=false) {
            if(refreshOnly && !File.Exists(Manifest)) return;
            foreach(string browser in Browsers) using(RegistryKey existing=Registry.CurrentUser.OpenSubKey(browser+Host))
                if(existing!=null && !String.Equals(existing.GetValue("") as string,Manifest,StringComparison.OrdinalIgnoreCase)) throw new Exception("浏览器连接注册冲突，请检查现有 IP Guard 安装。");
            Directory.CreateDirectory(Path.GetDirectoryName(Manifest));
            File.WriteAllText(Manifest,Data.Json().Serialize(new { name=Host,description="IP Guard browser connection",path=SystemPolicy.Exe,type="stdio",allowed_origins=new[] { "chrome-extension://"+BuildInfo.ExtensionId+"/" } }),new UTF8Encoding(false));
            foreach(string browser in Browsers) using(RegistryKey key=Registry.CurrentUser.CreateSubKey(browser+Host)) key.SetValue("",Manifest);
        }
        public static void Unregister() {
            foreach(string browser in Browsers) {
                bool own; using(RegistryKey key=Registry.CurrentUser.OpenSubKey(browser+Host)) own=key!=null && String.Equals(key.GetValue("") as string,Manifest,StringComparison.OrdinalIgnoreCase);
                if(own) Registry.CurrentUser.DeleteSubKey(browser+Host,false);
            }
            if(File.Exists(Manifest)) File.Delete(Manifest);
        }
        static byte[] Read(Stream input,int size) {
            byte[] bytes=new byte[size]; int offset=0;
            while(offset<size) { int count=input.Read(bytes,offset,size-offset); if(count==0) throw new EndOfStreamException(); offset+=count; }
            return bytes;
        }
        static void Send(Stream output,string json) {
            byte[] bytes=Encoding.UTF8.GetBytes(json);
            if(bytes.Length>16384) throw new IOException("浏览器消息过长");
            byte[] length=BitConverter.GetBytes((uint)bytes.Length); output.Write(length,0,4); output.Write(bytes,0,bytes.Length); output.Flush();
        }
        public static int Run(string origin) {
            if(origin!="chrome-extension://"+BuildInfo.ExtensionId+"/") return 1;
            using(Stream input=Console.OpenStandardInput()) using(Stream output=Console.OpenStandardOutput()) {
                try {
                    uint size=BitConverter.ToUInt32(Read(input,4),0);
                    if(size==0 || size>16384) return 1;
                    var request=Data.Json().Deserialize<Dictionary<string,object>>(Encoding.UTF8.GetString(Read(input,(int)size)));
                    if(request==null || !request.ContainsKey("action") || request["action"] as string!="watch" || !request.ContainsKey("protocol") || Convert.ToInt32(request["protocol"])!=3) return 1;
                    string version=request.ContainsKey("extensionVersion") ? request["extensionVersion"] as string : "";
                    if(version==null || (version!="" && (!Regex.IsMatch(version,@"^\d{1,5}(?:\.\d{1,5}){1,3}$") || version.Split('.').Any(part=>Int32.Parse(part)>65535)))) return 1;
                    using(NamedPipeClientStream pipe=new NamedPipeClientStream(".","IPGuard-Browser-"+SystemPolicy.Sid,PipeDirection.InOut,PipeOptions.Asynchronous)) {
                        pipe.Connect(2000);
                        byte[] metadata=Encoding.UTF8.GetBytes(Data.Json().Serialize(new { extensionVersion=version })+"\n"); pipe.Write(metadata,0,metadata.Length); pipe.Flush();
                        Task.Run(()=>{try { while(input.ReadByte()!=-1) { } } catch(IOException) { } finally { pipe.Dispose(); }});
                        using(StreamReader reader=new StreamReader(pipe,new UTF8Encoding(false),false,1024,true)) {
                            while(true) {
                                Task<string> read=Task.Run(()=>reader.ReadLine());
                                if(!read.Wait(2500) || read.Result==null) throw new IOException("守护连接已断开");
                                Send(output,read.Result);
                            }
                        }
                    }
                } catch(Exception error) {
                    string reason=error is UnauthorizedAccessException ? "浏览器连接权限不足，请升级并重启 IP Guard" : "本地守护连接失败 · "+error.GetBaseException().Message;
                    object permission=File.Exists(Released) && !(error is UnauthorizedAccessException) ? new { phase="released",currentIp="",expectedIp="",checkedAt="",reason="IP Guard 已完全退出并解除防护；重新打开后恢复校验" } : Offline(reason);
                    try { Send(output,Data.Json().Serialize(new { protocol=3,appVersion=BuildInfo.Version,services=new { claude=permission,chatgpt=permission } })); } catch(IOException) { }
                    return 1;
                }
            }
        }
    }
}
