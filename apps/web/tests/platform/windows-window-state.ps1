param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public static class IPGuardWindowState {
 public delegate bool Callback(IntPtr window,IntPtr parameter);
 [DllImport("user32.dll")] static extern bool EnumWindows(Callback callback,IntPtr parameter);
 [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr window,Callback callback,IntPtr parameter);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr window,StringBuilder text,int length);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string name,string title);
 static string Text(IntPtr window){var value=new StringBuilder(8192);GetWindowText(window,value,value.Capacity);return value.ToString();}
 public static string[] Read(int[] pids){var result=new List<string>();var selected=new HashSet<int>(pids);EnumWindows((window,parameter)=>{uint pid;GetWindowThreadProcessId(window,out pid);if(selected.Contains((int)pid)){result.Add("Window "+pid+": "+Text(window));EnumChildWindows(window,(child,unused)=>{string value=Text(child);if(value.Length>0)result.Add("Child: "+value);return true;},IntPtr.Zero);}return true;},IntPtr.Zero);return result.ToArray();}
}
'@
$states=@()
for($attempt=0;$attempt -lt 8;$attempt++){
 Start-Sleep -Seconds 2
 $pids=@(Get-Process -Name 'IP Guard' -ErrorAction SilentlyContinue | ForEach-Object {$_.Id})
 $states += [pscustomobject]@{Time=[DateTime]::UtcNow;Tray=[IPGuardWindowState]::FindWindow('Shell_TrayWnd',$null).ToInt64();Windows=[IPGuardWindowState]::Read([int[]]$pids)}
 $states | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Output -Encoding utf8
}
