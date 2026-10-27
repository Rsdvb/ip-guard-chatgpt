export const discoveryScript = `
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$shim=Get-Command claude.cmd -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$prefix=''; $npmError=''; $desktopError=''; $desktop=@(); $chatgptError=''; $chatgpt=@()
$native=@()
$nativePaths=@((Join-Path $env:USERPROFILE '.local\\bin\\claude.exe'))
$nativePaths+=@(Get-Command claude.exe -CommandType Application -All -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
foreach($file in $nativePaths | Select-Object -Unique) {
  if((Test-Path -LiteralPath $file -PathType Leaf) -and $file -notmatch '[\\\\/]node_modules[\\\\/]|[\\\\/]WindowsApps[\\\\/]') {
    $native+=@{path=$file;version=[string](Get-Item -LiteralPath $file).VersionInfo.ProductVersion}
  }
}
$npm=Get-Command npm.cmd -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if($npm) {
  try {
    $output=@(& $npm.Source prefix --global 2>$null)
    if($LASTEXITCODE -eq 0 -and $output.Count -gt 0) { $prefix=[string]$output[-1] }
    else { $npmError='npm 全局目录读取失败' }
  } catch { $npmError='npm 全局目录读取失败' }
}
try {
  Get-AppxPackage -Name Claude -ErrorAction Stop | ForEach-Object {
    $p=$_
    (Get-AppxPackageManifest -Package $p.PackageFullName -ErrorAction Stop).Package.Applications.Application | Where-Object { $_.Id -eq 'Claude' } | ForEach-Object {
      $desktop+=@{path=(Join-Path $p.InstallLocation $_.Executable);icon='';version=[string]$p.Version;source='msix'}
    }
  }
} catch { $desktopError='MSIX 安装信息读取失败' }
try {
  Get-AppxPackage -Name 'OpenAI.*' -ErrorAction Stop | ForEach-Object {
    $p=$_
    (Get-AppxPackageManifest -Package $p.PackageFullName -ErrorAction Stop).Package.Applications.Application | ForEach-Object {
      if($_.Executable) {
        $chatgpt+=@{path=(Join-Path $p.InstallLocation $_.Executable);version=[string]$p.Version;packageName=[string]$p.Name}
      }
    }
  }
} catch { $chatgptError='ChatGPT MSIX 安装信息读取失败' }
$keys=@('HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*')
Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Claude' } | ForEach-Object {
  $location=''
  if($_.InstallLocation) { $location=Join-Path $_.InstallLocation 'Claude.exe' }
  $desktop+=@{path=$location;icon=[string]$_.DisplayIcon;version=[string]$_.DisplayVersion;source='installer'}
}
@{shim=$(if($shim){[string]$shim.Source}else{''});npmPrefix=$prefix;npmError=$npmError;desktopError=$desktopError;desktop=@($desktop);native=@($native);chatgptError=$chatgptError;chatgpt=@($chatgpt)} | ConvertTo-Json -Depth 4 -Compress
`;
