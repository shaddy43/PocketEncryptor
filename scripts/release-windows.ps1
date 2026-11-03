# Builds the release files that are made on the Windows PC:
#   - the standalone Windows app (zip), the Windows CLI (zip) and the Android app (APK)
# into artifacts\release\v<version>\, with SHA-256 checksums.
#
# Run from the repo folder:   .\scripts\release-windows.ps1
# The Mac and iPhone files are made on the Mac with scripts/release-mac.sh.
#
# Android signing: without -KeyStore the APK is signed with the local debug key, which
# is fine for sideloading. For Google Play, pass your upload key (see RELEASING.md):
#   .\scripts\release-windows.ps1 -KeyStore "$HOME\keys\pocketencryptor-upload.jks" -KeyAlias upload

param(
    [string]$KeyStore,
    [string]$KeyAlias = "upload"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo

$appProj = "PocketEncryptor.App\PocketEncryptor.App.csproj"
$version = ([xml](Get-Content $appProj)).Project.PropertyGroup.ApplicationDisplayVersion | Where-Object { $_ } | Select-Object -First 1
$out = Join-Path $repo "artifacts\release\v$version"
Write-Host "PocketEncryptor $version -> $out" -ForegroundColor Cyan

if (Test-Path $out) { Remove-Item $out -Recurse -Force }
New-Item -ItemType Directory -Force $out | Out-Null

function Invoke-Step([string]$name, [scriptblock]$cmd) {
    Write-Host "`n== $name" -ForegroundColor Cyan
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "$name failed (exit code $LASTEXITCODE)" }
}

# No personal paths in the release: ContinuousIntegrationBuild writes neutral source paths
# (/_/...) into the dlls instead of this PC's folders (C:\Users\<you>\...), and DebugType=none
# leaves out the .pdb files. Start from empty Release folders so no older build is reused.
$clean = @("-p:ContinuousIntegrationBuild=true", "-p:DebugType=none")
foreach ($p in "PocketEncryptor.App", "PocketEncryptor.Core", "PocketEncryptor.Cli", "PocketEncryptor.Tests") {
    foreach ($d in "$p\bin\Release", "$p\obj\Release") { if (Test-Path $d) { Remove-Item $d -Recurse -Force } }
}

Invoke-Step "Tests" { dotnet test PocketEncryptor.Tests -c Release @clean --nologo }

# Windows app: self-contained folder, needs nothing installed on the target PC.
# Don't add -r win-x64: the project already targets it, and it breaks the restore for the other platforms.
# PublishReadyToRun=false keeps the zip under the 100 MB upload limit of the release page
# (Cloudflare): 88 MB instead of 103 MB, for about 0.3 s slower startup.
$winTfm = "net10.0-windows10.0.19041.0"
Invoke-Step "Windows app" {
    dotnet publish PocketEncryptor.App -f $winTfm -c Release -p:SelfContained=true -p:WindowsAppSDKSelfContained=true `
        -p:PublishReadyToRun=false @clean --nologo
}
$winPublish = "PocketEncryptor.App\bin\Release\$winTfm\win-x64\publish"
Compress-Archive "$winPublish\*" "$out\PocketEncryptor-$version-windows-x64.zip" -CompressionLevel Optimal

# CLI: one self-contained exe.
$cliOut = Join-Path $env:TEMP "pkec-cli-win-x64"
if (Test-Path $cliOut) { Remove-Item $cliOut -Recurse -Force }
Invoke-Step "Windows CLI" {
    dotnet publish PocketEncryptor.Cli -c Release -r win-x64 --self-contained `
        -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true @clean -o $cliOut --nologo
}
Compress-Archive "$cliOut\PocketEncryptor.exe" "$out\PocketEncryptor-CLI-$version-windows-x64.zip" -CompressionLevel Optimal
Remove-Item $cliOut -Recurse -Force

# Android: APK for sideloading; the AAB for Google Play is built only with your upload key.
$androidArgs = @("-f", "net10.0-android", "-c", "Release", "--nologo") + $clean
if ($KeyStore) {
    $secure = Read-Host "Password for $KeyStore" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    $env:PKEC_KEY_PASS = $plain
    $androidArgs += @("-p:AndroidKeyStore=true", "-p:AndroidSigningKeyStore=$KeyStore", "-p:AndroidSigningKeyAlias=$KeyAlias",
                      "-p:AndroidSigningKeyPass=env:PKEC_KEY_PASS", "-p:AndroidSigningStorePass=env:PKEC_KEY_PASS")
}
try {
    Invoke-Step "Android app" { dotnet build PocketEncryptor.App @androidArgs }
} finally {
    Remove-Item Env:\PKEC_KEY_PASS -ErrorAction SilentlyContinue
}
$androidBin = "PocketEncryptor.App\bin\Release\net10.0-android"
Copy-Item "$androidBin\com.shaddy43.pocketencryptor-Signed.apk" "$out\PocketEncryptor-$version-android.apk"
if ($KeyStore) {
    Copy-Item "$androidBin\com.shaddy43.pocketencryptor-Signed.aab" "$out\PocketEncryptor-$version-android-play.aab"
}

# Guard: the release must not contain this PC's user folder. The zips and the APK compress
# their dlls, so check the uncompressed build outputs they were made from.
$homePath = [regex]::Escape($HOME)
$built = foreach ($p in "PocketEncryptor.App", "PocketEncryptor.Core", "PocketEncryptor.Cli") {
    foreach ($d in "$p\bin\Release", "$p\obj\Release") { if (Test-Path $d) { $d } }
}
$leaks = Get-ChildItem $built -Recurse -File |
    Where-Object { $_.Name -like "PocketEncryptor*.dll" -or $_.Name -like "PocketEncryptor*.exe" } |
    Where-Object { [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($_.FullName)) -match $homePath }
if ($leaks) {
    Remove-Item $out -Recurse -Force
    throw "Release removed: these files contain your user folder path:`n" + ($leaks.FullName -join "`n")
}

# Checksums (the Mac script appends its own files to the same list).
$sums = Get-ChildItem $out -File | Where-Object Name -ne "SHA256SUMS.txt" | Sort-Object Name | ForEach-Object {
    "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
}
# LF line endings, not Set-Content's CRLF: `shasum -c` on a Mac or Linux reads a CR as part of the file name.
[IO.File]::WriteAllText("$out\SHA256SUMS.txt", (($sums -join "`n") + "`n"), [Text.Encoding]::ASCII)

# The release page sits behind Cloudflare, which refuses uploads over 100 MB.
Get-ChildItem $out -File | Where-Object Length -gt 100MB | ForEach-Object {
    Write-Warning ("{0} is {1:N1} MB: over the 100 MB upload limit of the release page" -f $_.Name, ($_.Length / 1MB))
}

Write-Host "`nDone:" -ForegroundColor Green
Get-ChildItem $out -File | Format-Table Name, @{ n = "MB"; e = { [math]::Round($_.Length / 1MB, 1) } } -AutoSize
