# Releasing PocketEncryptor

How to make a release: the downloadable builds first, then the notes for Google Play and the Apple App Store.

Windows commands are PowerShell on a Windows PC; Mac commands are bash in Terminal on a Mac. Run them from the repo folder. `<version>` below stands for the version you set in section 1, for example `2.0`.

Publishing your own build to a store? Change `ApplicationId` in `PocketEncryptor.App/PocketEncryptor.App.csproj` to an ID of your own first (sections 5 and 6 use `com.shaddy43.pocketencryptor`, the project's own ID).

## 1. Set the version

Two files, kept in step:

| Where | What | Example |
| --- | --- | --- |
| `PocketEncryptor.App/PocketEncryptor.App.csproj` | `ApplicationDisplayVersion`: the version people see | `2.0` |
| `Directory.Build.props` | `Version`: file version of the CLI and libraries | `2.0.0` |
| `PocketEncryptor.App/PocketEncryptor.App.csproj` | `ApplicationVersion`: build number | `1` |

The build number must go up by one for **every** upload to Google Play or App Store Connect, even a rejected one, and never go back down. Downloads on a release page don't need it to change.

## 2. Build the release files

On Windows (tests, Windows app, Windows CLI, Android APK):

```powershell
.\scripts\release-windows.ps1
```

On a Mac (tests, Mac app, Mac CLI for Apple Silicon and Intel):

```bash
bash scripts/release-mac.sh
```

Both write to `artifacts/release/v<version>/` (ignored by git), with a `SHA256SUMS.txt`. To have one checksum list, copy the Windows `SHA256SUMS.txt` into the Mac's folder before running the Mac script; it adds its own lines.

| File | What it is |
| --- | --- |
| `PocketEncryptor-<version>-windows-x64.zip` | Windows 10 (1809+) / 11 app. Unzip anywhere, start `PocketEncryptor.App.exe`. Nothing to install |
| `PocketEncryptor-<version>-macos.zip` | Mac app, Apple Silicon and Intel, macOS 14 Sonoma or later |
| `PocketEncryptor-<version>-android.apk` | Android 5.0+ app for sideloading |
| `PocketEncryptor-CLI-<version>-windows-x64.zip` | `PocketEncryptor.exe`, the command-line tool, one self-contained file |
| `PocketEncryptor-CLI-<version>-macos-arm64.zip` / `-x64.zip` | the same CLI for Apple Silicon / Intel Macs |

iPhone builds can't be downloaded: iOS installs apps only from the App Store, TestFlight, or Xcode (RUNBOOK section 4).

### Check before publishing

1. Unzip the Windows app in a new folder and start it; on the Mac, unzip the app and open it.
2. Install the APK on a phone or emulator (`adb install -r …apk`).
3. Encrypt a file on one platform and decrypt it on another (for example Android → Windows, Mac → Android). Check a wrong password is refused.
4. Run the CLI zip's `PocketEncryptor.exe` on a `.pkec` file from one of the apps.

## 3. Publish a release

1. Merge the release changes into `master`, then tag the merge and push the tag:

   ```powershell
   git checkout master
   git pull
   git tag -a v2.0.0 -m "PocketEncryptor 2.0"
   git push --follow-tags
   ```

2. On your Git host (GitHub, GitLab, Forgejo, …), create a new release from that tag, titled **PocketEncryptor `<version>`**.
3. Paste the release notes (template below), attach every file from `artifacts/release/v<version>/` (from both Windows and Mac) and publish. Some hosts limit the size of each upload, often to 100 MB; the Windows app zip is kept under that (RUNBOOK section 2).

### Release notes template

```markdown
PocketEncryptor encrypts a file with a password on one device and opens it on any other: Android, iPhone, Mac and Windows.

**New in <version>**
- …

**Downloads**
| Platform | File |
| --- | --- |
| Windows 10/11 | `PocketEncryptor-<version>-windows-x64.zip`: unzip, run `PocketEncryptor.App.exe` |
| macOS 14+ (Apple Silicon and Intel) | `PocketEncryptor-<version>-macos.zip`: unzip, drag to Applications |
| Android 5+ | `PocketEncryptor-<version>-android.apk` |
| iPhone | No download: iOS installs apps only from the App Store or TestFlight. To build it yourself, see RUNBOOK.md |
| Command line, Windows | `PocketEncryptor-CLI-<version>-windows-x64.zip` |
| Command line, Mac | `PocketEncryptor-CLI-<version>-macos-arm64.zip` (Apple Silicon) or `PocketEncryptor-CLI-<version>-macos-x64.zip` (Intel) |

**First launch.** These builds aren't signed by Microsoft or Apple:
- Windows: if SmartScreen says "Windows protected your PC", choose **More info → Run anyway**.
- macOS: if it says the app can't be opened or "is damaged", open **System Settings → Privacy & Security → Open Anyway**, or run `xattr -dr com.apple.quarantine /Applications/PocketEncryptor.app`. For the Mac command line, run `xattr -d com.apple.quarantine PocketEncryptor` in its folder.
- Android: allow your browser or Files app to **install unknown apps** when asked.

**Check a download** against `SHA256SUMS.txt`:
- macOS or Linux, in the download folder: `shasum -a 256 -c SHA256SUMS.txt --ignore-missing`
- Windows PowerShell: `Get-FileHash .\PocketEncryptor-<version>-windows-x64.zip` and compare the hash with the file's line
```

Drop the **First launch** part once the builds are signed (section 4).

## 4. Signing the desktop builds

Unsigned builds work, but each one warns on first launch (see the release notes). To remove the warnings (none of these has been tried with this project yet):

- **Windows:** sign `PocketEncryptor.App.exe` (and the CLI exe) with a code-signing certificate before zipping. Azure Trusted Signing is the cheapest option (a monthly fee, identity check required); a regular OV certificate from a certificate authority also works. Sign with `signtool sign /fd SHA256 /td SHA256 /tr <timestamp URL> …` as the certificate's provider documents.
- **Microsoft Store (optional):** free for individual developers, but the app has to be packaged as MSIX: set `WindowsPackageType` to `MSIX` for a store build.
- **macOS:** needs the Apple Developer Program (the same $99/year as the App Store, section 6). Create a **Developer ID Application** certificate, then sign with the hardened runtime and notarize. Follow Microsoft's guide "Publish a Mac Catalyst app for distribution outside the Mac App Store" for the exact properties. The outline:

  ```bash
  dotnet publish PocketEncryptor.App -f net10.0-maccatalyst -c Release -p:ValidateXcodeVersion=false \
    -p:EnableCodeSigning=true -p:UseHardenedRuntime=true \
    -p:CodesignKey="Developer ID Application: YOUR NAME (TEAMID)"
  # One-time: save the notary login (use an app-specific password from appleid.apple.com)
  xcrun notarytool store-credentials pkec --apple-id YOU@EXAMPLE.COM --team-id TEAMID
  ditto -c -k --keepParent PocketEncryptor.app PocketEncryptor.zip
  xcrun notarytool submit PocketEncryptor.zip --keychain-profile pkec --wait
  xcrun stapler staple PocketEncryptor.app      # then zip the stapled app again for the release
  ```

## 5. Google Play (Android)

Rough cost and time: $25 once; at least 2–3 weeks before the first public release, because of the closed test.

### One-time setup

1. Create a developer account at [play.google.com/console](https://play.google.com/console) (personal account, $25 once) and finish identity and device verification. Your name and country are shown on the store.
2. Create the **upload key**. Keep the file and its password safe and out of the repo: losing it means asking Google to reset it. (`*.jks` is ignored by git.)

   ```powershell
   New-Item -ItemType Directory -Force "$HOME\keys" | Out-Null
   & "$env:LOCALAPPDATA\Android\openjdk\bin\keytool.exe" -genkeypair -v `
     -keystore "$HOME\keys\pocketencryptor-upload.jks" -alias upload `
     -keyalg RSA -keysize 2048 -validity 10000
   ```

3. In Play Console, **Create app**: name *PocketEncryptor*, app, free. Keep **Play App Signing** on (the default): Google holds the key that signs what users install, and your upload key only proves uploads are yours.

### Each upload

1. Raise `ApplicationVersion` (section 1).
2. Build the signed bundle; the script asks for the key password:

   ```powershell
   .\scripts\release-windows.ps1 -KeyStore "$HOME\keys\pocketencryptor-upload.jks" -KeyAlias upload
   ```

   Upload `artifacts/release/v<version>/PocketEncryptor-<version>-android-play.aab` (Google Play takes only `.aab`, not `.apk`). The APK from the same run is signed with the upload key too; it's fine to attach it to the release page.

### Store listing and app content

Play Console asks for these before the first review (answers for this app):

| Section | Answer |
| --- | --- |
| Privacy policy | A public link to `PRIVACY.md` in the repository |
| App access | All functionality is available without special access (no login) |
| Ads | No ads |
| Content rating | IARC questionnaire, category *Utility, productivity, communication or other*; no to every content question |
| Target audience | 18 and over (or 13+). Avoid choosing under-13s: that brings in the Families policy |
| Data safety | No data collected, no data shared |
| Category | Tools |
| Graphics | 512×512 icon, 1024×500 feature graphic, at least 2 phone screenshots (take them on the emulator: `adb exec-out screencap -p > shot.png`) |
| Text | See [Store text](#store-text) below |

### Testing tracks, in order

1. **Internal testing:** up to 100 testers by email, available within minutes. Use it to check the Play-signed app installs and round-trips files.
2. **Closed testing (required):** personal accounts created after November 2023 must run a closed test with **at least 12 testers opted in for 14 days in a row** before production access. Start this as early as possible; friends and family with Android phones join through an opt-in link.
3. **Production:** apply for access in the Dashboard when the 14 days are up, then roll out. Review usually takes a few days.

### Things Play may flag

- **Target API level:** Play requires a recent target. The .NET 10 Android SDK targets API 36, which meets the current rule; it moves up every August.
- **16 KB memory pages:** required for new apps and updates. .NET 10 builds support them; if the Console warns, check the build uses the latest .NET Android workload.
- **Sideloaded APKs and developer verification:** Google is rolling out a rule that apps installed outside Play on certified Android phones must come from a verified developer (starting in some countries in 2026, wider in 2027). Once your Play account is verified, register the app's package name (`ApplicationId`) with it so the APK from the release page keeps installing. Check the current status in Play Console.

## 6. Apple App Store (iPhone, and optionally Mac)

Rough cost and time: $99/year (covers iPhone, Mac App Store and Mac notarization); 1–2 days for enrollment, about a day per review.

### One-time setup (on the Mac)

1. Enroll in the [Apple Developer Program](https://developer.apple.com/programs/enroll/) as an individual. Your legal name is shown as the seller.
2. In Xcode → Settings → Accounts, sign in with the same Apple ID; the paid team now appears next to the Personal Team.
3. In the developer portal ([developer.apple.com/account](https://developer.apple.com/account)), under **Certificates, Identifiers & Profiles**:
   - **Identifiers → +**: App ID with the app's bundle ID (`ApplicationId`, e.g. `com.shaddy43.pocketencryptor`). If it says the ID isn't available, a free Personal Team (RUNBOOK section 4) may still hold it. Ask Apple Developer Support to release it, or pick a new ID and change `ApplicationId` in the app project.
   - **Certificates → +**: **Apple Distribution** (Xcode → Settings → Accounts → Manage Certificates can create it too).
   - **Profiles → +**: **App Store Connect** profile for that App ID and certificate, named e.g. `PocketEncryptor App Store`. Download it and double-click to install.
4. In [App Store Connect](https://appstoreconnect.apple.com) → Apps → **+ New App**: iOS, name *PocketEncryptor*, primary language English, bundle ID from step 3, SKU `pocketencryptor`.

### Before the first build

- **Xcode version:** uploads must be built with a released (not beta) Xcode and SDK. The commands here use `-p:ValidateXcodeVersion=false` because the .NET iOS workload often trails Xcode by a minor version. If App Store Connect rejects the build, install the Xcode version the workload names (see the build warning) and select it with `sudo xcode-select -s`.
- **Encryption export question:** every upload asks whether the app uses encryption; answering in `Info.plist` skips the question. PocketEncryptor's purpose is encryption, so this is a legal declaration you make, not a technical setting. On Apple platforms .NET's AES-GCM and PBKDF2 run on Apple's own CryptoKit and CommonCrypto, which may fit the "only uses encryption in Apple's operating system" choice; otherwise choose "standard encryption algorithms". Read Apple's [Complying with encryption export regulations](https://developer.apple.com/documentation/security/complying-with-encryption-export-regulations) and decide, then add the matching `ITSAppUsesNonExemptEncryption` key to `Platforms/iOS/Info.plist`. Selling in France with standard algorithms may need a French declaration; you can leave France out of the territories instead.
- **iPad:** the app is enabled for iPad too (`UIDeviceFamily` 1 and 2), so App Store Connect needs iPad screenshots as well. To ship iPhone-only, remove `<integer>2</integer>` from `UIDeviceFamily`.

### Each upload

1. Raise `ApplicationVersion` (section 1).
2. Build the signed IPA:

   ```bash
   dotnet publish PocketEncryptor.App -f net10.0-ios -c Release -p:ValidateXcodeVersion=false \
     -p:RuntimeIdentifier=ios-arm64 -p:ArchiveOnBuild=true \
     -p:CodesignKey="Apple Distribution: YOUR NAME (TEAMID)" \
     -p:CodesignProvision="PocketEncryptor App Store"
   ls PocketEncryptor.App/bin/Release/net10.0-ios/ios-arm64/publish/*.ipa
   ```

3. Upload the `.ipa` with Apple's free **Transporter** app (Mac App Store): sign in, drag the file in, **Deliver**. After 10–30 minutes it appears in App Store Connect → TestFlight.
4. **TestFlight:** add yourself as an internal tester and install from the TestFlight app on the iPhone. Unlike the free-Apple-ID install, it lasts 90 days. Run the cross-platform check from section 2.
5. **Submit:** fill in the version page and **Add for Review**.

### App Store Connect answers

| Section | Answer |
| --- | --- |
| App Privacy | Data Not Collected; privacy policy URL as for Google Play |
| Age rating | None of the content categories: 4+ |
| Category | Utilities (secondary: Productivity) |
| Screenshots | 6.9" iPhone (1320×2868; the iPhone 17 Pro Max simulator: `xcrun simctl io booted screenshot shot.png`), plus 13" iPad if iPad stays on |
| Review notes | "No account or network needed. To test: Choose files → pick any file → enter a password twice → Encrypt → choose a folder. Choose the resulting .pkec file and enter the same password to decrypt it." |
| Text | See [Store text](#store-text) |

### Mac App Store (optional)

The Mac app is already sandboxed, as the Mac App Store requires. It needs a **Mac App Store** provisioning profile, an **Apple Distribution** and a **Mac Installer Distribution** certificate, and a signed `.pkg` (`-p:CreatePackage=true -p:EnablePackageSigning=true`), uploaded with Transporter. Not tried yet; outside the store, the notarized download (section 4) is simpler.

## Store text

Ready to paste into both stores.

**Name:** PocketEncryptor

**Subtitle (Apple, ≤ 30):** Encrypt files, open anywhere

**Short description (Google, ≤ 80):** Lock files with a password. Open them on Android, iPhone, Mac or Windows.

**Keywords (Apple, ≤ 100):** encrypt,decrypt,file,password,aes,privacy,secure,vault,lock,cross-platform

**Description:**

```text
Lock a file with a password on one device, and open it on any other.

PocketEncryptor turns any file (a document, a photo, a backup) into an encrypted .pkec file that only your password can open. The same file decrypts on Android, iPhone, iPad, Mac and Windows, so you can encrypt on your phone and open on your laptop, or the other way round.

SIMPLE
• Pick files, type a password, done. Choose .pkec files and the app decrypts them instead.
• Do many files at once; each one shows its own result.
• Bring files in with Share, Open with, or drag and drop.

SAFE BY DESIGN
• AES-256-GCM encryption, with the key made from your password by PBKDF2 (600,000 rounds).
• A wrong password or a damaged file is detected; you never get a broken output.
• Nothing is overwritten: if a name is taken, the result gets a new one.
• Purge (optional): replaces originals with their encrypted copies, only after checking each one decrypts.

PRIVATE
• No account, no internet, no ads, no tracking. The app asks for no permissions.
• Your password is never stored. Forget it and nobody, including us, can open your files.
```
