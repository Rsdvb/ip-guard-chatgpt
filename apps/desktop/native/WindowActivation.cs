using System;
using System.Runtime.InteropServices;
namespace IpGuard {
    public static class WindowActivation {
        delegate bool EnumWindow(IntPtr window,IntPtr context);
        [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindow callback,IntPtr context);
        [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
        [DllImport("user32.dll")] static extern bool IsIconic(IntPtr window);
        [DllImport("user32.dll")] static extern int GetWindowTextLength(IntPtr window);
        [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr window,uint command);
        [DllImport("user32.dll",EntryPoint="GetWindowLongPtrW")] static extern IntPtr GetWindowLongPtr(IntPtr window,int index);
        [StructLayout(LayoutKind.Sequential)] struct Rectangle { public int left,top,right,bottom; }
        [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr window,out Rectangle rectangle);
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
        [DllImport("user32.dll")] static extern bool ShowWindowAsync(IntPtr window,int command);
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr window);
        [DllImport("user32.dll")] public static extern bool AllowSetForegroundWindow(uint pid);
        public static bool ShowProtectedWindow(IntPtr job,out bool foreground) {
            IntPtr found=IntPtr.Zero,hidden=IntPtr.Zero;
            EnumWindows(delegate(IntPtr window,IntPtr context) {
                if(GetWindowTextLength(window)==0 || GetWindow(window,4)!=IntPtr.Zero || (GetWindowLongPtr(window,-20).ToInt64()&0x80)!=0) return true;
                uint pid; GetWindowThreadProcessId(window,out pid);
                IntPtr process=Win32.OpenProcess(0x1000,false,pid);
                if(process==IntPtr.Zero) return true;
                try {
                    bool inside;
                    if(Win32.IsProcessInJob(process,job,out inside) && inside) {
                        if(IsWindowVisible(window)) { found=window; return false; }
                        Rectangle rectangle;
                        if(hidden==IntPtr.Zero && GetWindowRect(window,out rectangle) && rectangle.right-rectangle.left>=100 && rectangle.bottom-rectangle.top>=80) hidden=window;
                    }
                }
                finally { Win32.CloseHandle(process); }
                return true;
            },IntPtr.Zero);
            foreground=false;
            if(found==IntPtr.Zero) found=hidden;
            if(found==IntPtr.Zero) return false;
            if(!IsWindowVisible(found) || IsIconic(found)) ShowWindowAsync(found,9);
            foreground=SetForegroundWindow(found);
            return true;
        }
    }
}
