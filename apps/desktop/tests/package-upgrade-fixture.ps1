param([Parameter(Mandatory=$true)][string]$Root,[Parameter(Mandatory=$true)][ValidateSet('install','remove')][string]$Action,[int]$Version=1)
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') { throw 'This fixture only runs on an isolated GitHub-hosted Windows runner' }
$identity='IPGuard.UpgradeFixture'
if ($Action -eq 'remove') {
    Get-AppxPackage -Name $identity | Remove-AppxPackage
    if (Test-Path -LiteralPath "$Root/thumbprint.txt") {
        $thumbprint=(Get-Content -LiteralPath "$Root/thumbprint.txt" -Raw).Trim()
        Remove-Item -LiteralPath "Cert:\LocalMachine\TrustedPeople\$thumbprint" -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint" -ErrorAction SilentlyContinue
    }
    exit 0
}
$sdk=Get-ChildItem -Path 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makeappx.exe' | Sort-Object FullName -Descending | Select-Object -First 1
if (!$sdk) { throw 'Windows SDK MakeAppx not found' }
$sign=Join-Path $sdk.DirectoryName 'signtool.exe'
$password='IPGuard-CI-fixture-only'
if (!(Test-Path -LiteralPath "$Root/fixture.pfx")) {
    $certificate=New-SelfSignedCertificate -Type Custom -Subject 'CN=IPGuard CI Fixture' -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation 'Cert:\CurrentUser\My' -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3','2.5.29.19={text}')
    $certificate.Thumbprint | Set-Content -LiteralPath "$Root/thumbprint.txt"
    Export-PfxCertificate -Cert $certificate -FilePath "$Root/fixture.pfx" -Password (ConvertTo-SecureString -String $password -AsPlainText -Force) | Out-Null
    Export-Certificate -Cert $certificate -FilePath "$Root/fixture.cer" | Out-Null
    Import-Certificate -FilePath "$Root/fixture.cer" -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
}
$source=New-Item -ItemType Directory -Path "$Root/v$Version/app" -Force
Copy-Item -LiteralPath "$Root/fixture.exe" -Destination "$source/Fixture.exe"
Copy-Item -LiteralPath "$Root/logo.png" -Destination "$Root/v$Version/logo.png"
$manifest=@"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10" xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" IgnorableNamespaces="uap rescap">
  <Identity Name="$identity" Publisher="CN=IPGuard CI Fixture" Version="$Version.0.0.0" ProcessorArchitecture="x64" />
  <Properties><DisplayName>IP Guard CI Fixture</DisplayName><PublisherDisplayName>IP Guard CI</PublisherDisplayName><Logo>logo.png</Logo></Properties>
  <Resources><Resource Language="en-us" /></Resources>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.26100.0" /></Dependencies>
  <Applications><Application Id="App" Executable="app\Fixture.exe" EntryPoint="Windows.FullTrustApplication"><uap:VisualElements DisplayName="IP Guard CI Fixture" Description="Isolated upgrade regression" Square150x150Logo="logo.png" Square44x44Logo="logo.png" BackgroundColor="transparent" /></Application></Applications>
  <Capabilities><rescap:Capability Name="runFullTrust" /></Capabilities>
</Package>
"@
[IO.File]::WriteAllText("$Root/v$Version/AppxManifest.xml",$manifest,[Text.UTF8Encoding]::new($false))
& $sdk.FullName pack /d "$Root/v$Version" /p "$Root/v$Version.msix" /o
if ($LASTEXITCODE -ne 0) { throw 'MakeAppx failed' }
& $sign sign /fd SHA256 /a /f "$Root/fixture.pfx" /p $password "$Root/v$Version.msix"
if ($LASTEXITCODE -ne 0) { throw 'Fixture signing failed' }
Add-AppxPackage -Path "$Root/v$Version.msix"
$package=Get-AppxPackage -Name $identity
if (!$package -or $package.Version -ne "$Version.0.0.0") { throw 'Fixture registration failed' }
@{fullName=$package.PackageFullName;executable=(Join-Path $package.InstallLocation 'app\Fixture.exe')} | ConvertTo-Json -Compress
