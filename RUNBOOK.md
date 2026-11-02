# PocketEncryptor Daily Runbook

Last updated: 2026-11-02

Run every command from PowerShell on the Windows PC, in the repo folder, except section 4 (iPhone), which runs in Terminal on the Mac.

## 1. Start of day

Get the latest `master` from the self-hosted server and check that the tests pass (73 at last count).

```powershell
cd $HOME\source\repos\PocketEncryptor
git checkout master
git pull selfhosted master
dotnet test PocketEncryptor.Tests
```

Pulling needs no passphrase: the self-hosted repo is fetched over HTTPS.

## 2. Windows app

While developing, build and start the Debug app in one step. Close the app before building again: a running app locks its files.

```powershell
dotnet build PocketEncryptor.App -f net10.0-windows10.0.19041.0 -t:Run
```

For everyday use, build the Release app once after each merge, then start the exe directly:

```powershell
dotnet build PocketEncryptor.App -f net10.0-windows10.0.19041.0 -c Release
& ".\PocketEncryptor.App\bin\Release\net10.0-windows10.0.19041.0\win-x64\PocketEncryptor.App.exe"
```

Optional desktop shortcut to that exe (run once from the repo folder):

```powershell
$exe = Resolve-Path ".\PocketEncryptor.App\bin\Release\net10.0-windows10.0.19041.0\win-x64\PocketEncryptor.App.exe"
$s = (New-Object -ComObject WScript.Shell).CreateShortcut("$([Environment]::GetFolderPath('Desktop'))\PocketEncryptor.lnk")
$s.TargetPath = "$exe"; $s.Save()
```

To run the app on another PC, publish a standalone folder. It needs nothing installed there: no .NET, no Windows App SDK.

```powershell
dotnet publish PocketEncryptor.App -f net10.0-windows10.0.19041.0 -c Release -p:SelfContained=true -p:WindowsAppSDKSelfContained=true
Compress-Archive ".\PocketEncryptor.App\bin\Release\net10.0-windows10.0.19041.0\win-x64\publish\*" "$HOME\Desktop\PocketEncryptor-win-x64.zip" -Force
```

Unzip it anywhere on the other PC and start `PocketEncryptor.App.exe`, keeping the files together (about 280 MB unzipped, 100 MB zipped). Don't add `-r win-x64`: it breaks the restore for the other platforms.

## 3. Android app

Attach one device, either the emulator or your phone, then run or install the app. Keep only one attached so the build knows where to deploy.

```powershell
$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"

# Emulator (opens in its own window)
Start-Process "$env:LOCALAPPDATA\Android\Sdk\emulator\emulator.exe" "-avd Medium_Phone_API_37.0"

# Check the device is attached: it should be listed as "device"
& $adb devices
```

For your phone instead of the emulator: Settings → About phone → tap Build number 7 times, then Developer options → USB debugging on. Plug it in and accept the prompt.

Run the Debug app (builds, installs and starts it):

```powershell
dotnet build PocketEncryptor.App -f net10.0-android -t:Run
```

Or build and install the Release app, then open PocketEncryptor from the app drawer:

```powershell
dotnet build PocketEncryptor.App -f net10.0-android -c Release
& $adb install -r ".\PocketEncryptor.App\bin\Release\net10.0-android\com.shaddy43.pocketencryptor-Signed.apk"
```

Without a cable: copy that APK to the phone and tap it in Files (allow Files to install unknown apps when asked).

Moving files between the PC and the device:

```powershell
& $adb push "$HOME\Documents\secret.pdf" /sdcard/Download/
& $adb pull /sdcard/Download/secret.pdf.pkec "$HOME\Downloads\"
```

## 4. iPhone (on the Mac)

Run these in Terminal on the Mac, with the iPhone plugged in by USB. Not tried on a real iPhone yet: if signing fails in step 4, keep the error.

With a free Apple ID the app stops opening after 7 days; repeat steps 4 and 5 to renew it. A paid Apple Developer account ($99/year) lasts a year and adds TestFlight.

One-time setup:

1. In Xcode, go to Settings, then Accounts, then **+**, and add your Apple ID.
2. Get a signing profile: in Xcode, make a new empty iOS App project with the bundle ID `com.shaddy43.pocketencryptor`. Select your iPhone and press Run once. Xcode then creates the certificate and profile. You can delete the project afterwards.
3. On the iPhone, turn on Settings, then Privacy & Security, then **Developer Mode**. The phone restarts. Plug it in and tap **Trust**.

Each install:

4. Build for the phone:

   ```bash
   cd ~/PocketEncryptor   # wherever the repo is on the Mac
   dotnet build PocketEncryptor.App -f net10.0-ios -c Release \
     -p:RuntimeIdentifier=ios-arm64 -p:ValidateXcodeVersion=false
   ```

5. Install it:

   ```bash
   xcrun devicectl list devices    # copy your iPhone's identifier
   xcrun devicectl device install app --device <ID> \
     PocketEncryptor.App/bin/Release/net10.0-ios/ios-arm64/PocketEncryptor.App.app
   ```

6. The first time only: on the iPhone, go to Settings, then General, then **VPN & Device Management**, tap your Apple ID and choose Trust.

## 5. CLI

Build it once after each merge and give it a short name for this terminal session. It asks for the password itself, with masked input.

```powershell
dotnet build PocketEncryptor.Cli -c Release
Set-Alias pkec (Resolve-Path ".\PocketEncryptor.Cli\bin\Release\net10.0\PocketEncryptor.exe").Path

pkec notes.txt notes.txt.pkec -E        # encrypt (asks twice)
pkec notes.txt.pkec notes.txt -D        # decrypt
pkec .\my_folder .\my_folder_enc -r     # encrypt every file in a folder, same password
```

- `-r` leaves the originals untouched and writes `.pkec` copies with the same subfolders. Decrypt them one at a time with `-D`.
- End encrypted names in `.pkec`: the apps then suggest the original name when decrypting. Files from the CLI, the Windows app and the Android app all decrypt in each other.

## 6. Using the app

The app picks the mode for you: choose only `.pkec` files and it decrypts, choose anything else and it encrypts.

1. Press **Choose files** and pick one or more files.
2. Enter the password (twice when encrypting).
3. Press the button. One file opens a Save dialog; several files ask for a folder once.
4. Read each file's result in the list. A failed file (for example, a different password) can be retried on its own by pressing the button again.

Getting files in without the picker:

- **Windows:** drag files from Explorer onto the window.
- **Android:** in Files or Gallery, choose **Share → PocketEncryptor**, or tap a `.pkec` file and choose **Open with → PocketEncryptor**.

**Purge** (Encrypt mode, Windows and Android) replaces the originals with their encrypted files. It asks every time, checks that each encrypted file decrypts before touching anything, and unticks itself after the run.

- On Windows the encrypted file goes next to the original; on Android you pick a folder (not the Download root).
- Originals it can't delete are kept and listed: read-only files, and files shared from another app.
- There is no undo and no recovery without the password.

## 7. End of day

Work on a branch, push it to the self-hosted server, and merge there. GitHub updates itself from the mirror, so never push to `origin`.

```powershell
git checkout -b feature/my-change           # once, before you start
git add -A
git commit -m "What changed and why"
git push -u selfhosted feature/my-change     # asks for your SSH key passphrase
```

1. Open a pull request into `master` at [git.shaddy43.com/shaddy43/PocketEncryptor](https://git.shaddy43.com/shaddy43/PocketEncryptor) and merge it.
2. Bring the merge home and drop the branch:

```powershell
git checkout master
git pull selfhosted master
git branch -d feature/my-change
```

A plain `git push` also goes to the self-hosted server: it's set as the default push remote. Claude's memory folder (`.claude/memory/`) is ignored by git and never pushed.

## 8. When something breaks

| Problem | Fix |
| --- | --- |
| Windows build: file is locked or in use | Close the app, or run `Get-Process PocketEncryptor.App \| Stop-Process` |
| Android build: XA0033 or an unsupported JDK | The build uses JDK 17 in `%LOCALAPPDATA%\Android\openjdk`. If that folder is gone, rerun the install command in the README (Building and testing) |
| `adb devices` is empty or says unauthorized | Replug the phone and accept the prompt, or run `& $adb kill-server` and try again |
| `-t:Run` complains about several devices | Close the emulator or unplug the phone, so only one is attached |
| Android app closes right after a Debug `-t:Run` | Run `& $adb shell am force-stop com.shaddy43.pocketencryptor`, then open it again |
| Files pushed with adb don't show under Downloads in the picker | Open ☰, then the device name, then Download |
| Android won't use Download as the output folder | Choose or create a folder inside Download |
| "Wrong password" | Nothing was written. Passwords are case-sensitive: check Caps Lock |
| `git push` says Permission denied (publickey) | Push from your own terminal, so it can ask for the SSH key passphrase |
