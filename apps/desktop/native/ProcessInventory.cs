using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace IpGuard {
    public static class ProcessInventory {
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Entry {
            public uint size,usage,pid; public UIntPtr heap; public uint module,threads,parent; public int priority; public uint flags;
            [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string image;
        }
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint pid);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool Process32First(IntPtr snapshot,ref Entry entry);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool Process32Next(IntPtr snapshot,ref Entry entry);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool ProcessIdToSessionId(uint pid,out uint session);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
        public sealed class Row { public int pid,parent; }
        public sealed class Result {
            public int session,unknown; public string username; public bool selfInTree,mixedServices;
            public Row[] processes;
        }
        static bool ContainsAncestor(uint pid,HashSet<uint> selected,Dictionary<uint,uint> parents) {
            var visited=new HashSet<uint>();
            while(pid>0 && visited.Add(pid)) { if(selected.Contains(pid)) return true; if(!parents.TryGetValue(pid,out pid)) break; }
            return false;
        }
        public static object Read(uint controller) {
            uint session=(uint)Process.GetCurrentProcess().SessionId;
            string sid=WindowsIdentity.GetCurrent().User.Value,username=WindowsIdentity.GetCurrent().Name;
            var rows=new List<Entry>(); var parents=new Dictionary<uint,uint>();
            IntPtr snapshot=CreateToolhelp32Snapshot(2,0);
            if(snapshot==new IntPtr(-1)) throw new System.ComponentModel.Win32Exception();
            try {
                Entry entry=new Entry { size=(uint)Marshal.SizeOf(typeof(Entry)) };
                Win32.Check(Process32First(snapshot,ref entry));
                do { rows.Add(entry); parents[entry.pid]=entry.parent; } while(Process32Next(snapshot,ref entry));
                if(Marshal.GetLastWin32Error()!=18) throw new System.ComponentModel.Win32Exception();
            } finally { Win32.CloseHandle(snapshot); }
            var results=new Dictionary<string,Result>();
            foreach(string service in new[] { "claude","chatgpt" }) {
                string image=service=="claude" ? "Claude.exe" : "ChatGPT.exe";
                string other=service=="claude" ? "ChatGPT.exe" : "Claude.exe";
                var selected=new List<Row>(); int unknown=0;
                foreach(Entry row in rows.Where(value=>String.Equals(value.image,image,StringComparison.OrdinalIgnoreCase))) {
                    uint found;
                    if(!ProcessIdToSessionId(row.pid,out found)) { unknown++; continue; }
                    if(found!=session) continue;
                    IntPtr process=Win32.OpenProcess(0x1000,false,row.pid),token=IntPtr.Zero;
                    if(process==IntPtr.Zero) { unknown++; continue; }
                    try {
                        if(!OpenProcessToken(process,8,out token)) { unknown++; continue; }
                        using(var identity=new WindowsIdentity(token)) if(identity.User.Value==sid)
                            selected.Add(new Row { pid=(int)row.pid,parent=(int)row.parent });
                    } finally { if(token!=IntPtr.Zero) Win32.CloseHandle(token); Win32.CloseHandle(process); }
                }
                var ids=new HashSet<uint>(selected.Select(row=>(uint)row.pid));
                results[service]=new Result {
                    session=(int)session,username=username,unknown=unknown,processes=selected.ToArray(),
                    selfInTree=ContainsAncestor(controller,ids,parents),
                    mixedServices=rows.Any(row=>String.Equals(row.image,other,StringComparison.OrdinalIgnoreCase) && ContainsAncestor(row.pid,ids,parents))
                };
            }
            return results;
        }
    }
}
