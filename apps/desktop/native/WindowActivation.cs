using System;
using System.Runtime.InteropServices;
namespace IpGuard {
    public static class WindowActivation {
        delegate bool EnumWindow(IntPtr window,IntPtr context);
        [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindow callback,IntPtr context);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
        [DllImport("user32.dll")] static extern bool IsIconic(IntPtr window);
        [DllImport("user32.dll")] static extern int GetWindowTextLength(IntPtr window);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
        [DllImport("user32.dll")] static extern bool ShowWindowAsync(IntPtr window,int command);
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr window);
        [DllImport("user32.dll")] public static extern bool AllowSetForegroundWindow(uint pid);
        public static bool ShowProtectedWindow(IntPtr job,out bool foreground) {
            IntPtr found=IntPtr.Zero;
            EnumWindows(delegate(IntPtr window,IntPtr context) {
                if(!IsWindowVisible(window) || GetWindowTextLength(window)==0) return true;
                uint pid; GetWindowThreadProcessId(window,out pid);
                IntPtr process=Win32.OpenProcess(0x1000,false,pid);
                if(process==IntPtr.Zero) return true;
                try { bool inside; if(Win32.IsProcessInJob(process,job,out inside) && inside) { found=window; return false; } }
                finally { Win32.CloseHandle(process); }
                return true;
            },IntPtr.Zero);
            foreground=false;
            if(found==IntPtr.Zero) return false;
            if(IsIconic(found)) ShowWindowAsync(found,9);
            foreground=SetForegroundWindow(found);
            return true;
        }
    }
}
