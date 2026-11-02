# PocketEncryptor

A personal tool for encrypting and decrypting files with a passphrase, using
AES-256-GCM (authenticated encryption) and PBKDF2-HMAC-SHA256 key derivation.

It comes as a desktop/mobile app (Windows, macOS, iOS, Android) and a CLI. Both
use the same core library and file format, so a file encrypted on one device
decrypts on any other.

## App

Pick one or more files, enter a password, and save the results wherever you like:

- Picking only `.pkec` files switches to **Decrypt** automatically; anything
  else is **Encrypt**.
- One file: the native Save dialog opens with the suggested name (on iOS and
  macOS you choose a folder instead). Several files: choose a folder once, and
  every result is saved there. Each file is
  listed with its own result, so one failure (say, a file with a different
  password) doesn't stop the rest; press the button again to retry just those.
- With a mixed selection, Encrypt skips files that are already encrypted and
  Decrypt skips files that aren't, so both can be handled in two runs.
- Each result is produced (and, when decrypting, fully verified) in the app's
  private storage first, then copied to the location you choose. A wrong
  password never produces an output file.
- The app never overwrites anything: if a name is taken, the result gets a
  numbered name such as `photo (1).jpg.pkec`. It needs no network access and
  requests no permissions.
- On Android, the system folder picker won't offer the root of Download or of
  the storage itself; choose or create a folder inside them.

Getting files into the app without the picker:

- **Android:** select files in Files, Gallery or any other app and choose
  **Share → PocketEncryptor**, or tap a `.pkec` file and choose
  **Open with → PocketEncryptor**.
- **Windows:** drag files from File Explorer onto the window. To open `.pkec`
  files by double-clicking, right-click one, choose **Open with → Choose
  another app → Choose an app on your PC**, pick `PocketEncryptor.App.exe` and
  tick **Always**. Each "Open with" starts its own window for now.

### Purge

Tick **Purge** (Encrypt mode, Windows and Android) to replace your files with
their encrypted versions. It asks for confirmation every time, and for each file:

1. The encrypted file is saved: next to the original on Windows; in a folder
   you choose on Android.
2. It's read back and fully decrypted with your password as a check. If that
   fails, it's removed and the original is kept.
3. Only then is the original overwritten with random data and deleted, along
   with any private copy the app made of it.

Some originals can't be deleted by the app, and are kept and listed: files
shared to it from another app, read-only files, and files stored where the
owning app doesn't allow deleting (Android). Gallery photos are better
encrypted through the Files app, since gallery apps keep their own trash and
cloud copies.

Overwriting before deleting defeats undelete tools and helps on hard disks,
but no app can guarantee that nothing survives: SSDs and phone storage write
changes to fresh cells, some file systems (APFS, f2fs) keep old blocks, and
backups, cloud sync, snapshots, the Recycle Bin and thumbnail caches hold
copies of their own. Turn on full-disk encryption (BitLocker, FileVault;
phones have it built in) so that whatever does remain is unreadable.

## CLI

### Usage

    PocketEncryptor <input> <output> <-E|-D|-r>

- `-E`  Encrypt `input_file`, writing the result to `output_file`.
        You will be prompted to enter and confirm a passphrase (masked input).
- `-D`  Decrypt `input_file`, writing the result to `output_file`.
        You will be prompted to enter the passphrase used at encryption time.
- `-r`  Recursively encrypt **every file** under `input_dir`, writing encrypted
        copies into `output_dir` and preserving the subfolder structure. Each
        encrypted file gets a `.pkec` extension (e.g. `notes.txt` →
        `notes.txt.pkec`). You are prompted once, and the same passphrase is
        used for all files. Originals are left untouched. To decrypt them later,
        run `-D` on each `.pkec` file.

### Example

    dotnet run --project PocketEncryptor.Cli -- secret.docx secret.docx.enc -E
    dotnet run --project PocketEncryptor.Cli -- secret.docx.enc restored.docx -D
    dotnet run --project PocketEncryptor.Cli -- ./my_folder ./encrypted_folder -r

## Security notes

- AES-256-GCM provides confidentiality and integrity: a wrong passphrase or a
  tampered file is detected and rejected with a clear error, rather than
  silently producing garbage output.
- Files are encrypted in authenticated 64 KiB chunks, so files of any size are
  streamed with constant memory (important on phones). Reordering, dropping,
  truncating or appending chunks is detected.
- Decrypted output is written to a temporary file and only moved into place
  once the whole file has authenticated, so a failure never leaves a partial
  or corrupt output file.
- A random 16-byte salt and nonce prefix are generated for every encryption
  and stored (not secret) in the output file's header, so encrypting the same
  file twice with the same passphrase yields different ciphertext.
- The passphrase is Unicode-normalized (NFC) and passed through
  PBKDF2-HMAC-SHA256 with 600,000 iterations before being used as the AES key.
  It is entered interactively and never appears as a command-line argument,
  in shell history, or in `ps` output.
- Files from the previous release (format v1) still decrypt. New files are
  always written as v2.
- Keys, password bytes and plaintext buffers are kept in pinned memory (never
  moved or copied by the .NET garbage collector) and zeroed as soon as they're
  done with. The password text itself can't be wiped: .NET strings are
  immutable, and the OS text box holds its own copy.

## File format (v2)

    [4 bytes]  magic "PKEC"
    [1 byte]   format version 0x02
    [4 bytes]  PBKDF2 iterations (uint32, big-endian)
    [4 bytes]  chunk size in bytes (uint32, big-endian; default 65536)
    [16 bytes] PBKDF2 salt
    [7 bytes]  random nonce prefix
    then one or more chunks, each:
    [<= chunk size bytes] ciphertext
    [16 bytes]            AES-GCM authentication tag

Chunk `i` is sealed with nonce `prefix || i (uint32 BE) || final_flag (1 byte)`
and the 36-byte header as associated data. Every chunk except the last holds
exactly `chunk size` bytes of plaintext. See `PocketEncryptor.Core/PkecFormat.cs`
for details, including the legacy v1 layout.

## Project layout

    PocketEncryptor.Core/   crypto + file format, shared by every front end
    PocketEncryptor.App/    .NET MAUI app: Windows, macOS, iOS, Android
    PocketEncryptor.Cli/    command-line tool (builds PocketEncryptor.exe)
    PocketEncryptor.Tests/  xUnit tests for the core

## Building and testing

Requires the .NET 10 SDK. The app also needs the MAUI workload
(`dotnet workload install maui`).

    dotnet test PocketEncryptor.Tests        # core tests
    dotnet build PocketEncryptor.Cli         # CLI

Run the app:

    # Windows
    dotnet build PocketEncryptor.App -f net10.0-windows10.0.19041.0 -t:Run

    # Android (needs the Android SDK; see below), with a device or emulator attached
    dotnet build PocketEncryptor.App -f net10.0-android -t:Run

    # macOS / iOS: on a Mac with Xcode
    dotnet build PocketEncryptor.App -f net10.0-maccatalyst -t:Run
    dotnet build PocketEncryptor.App -f net10.0-ios -t:Run

Building the whole solution (`dotnet build` at the root) builds the app for
every platform, so it needs the Android SDK (API 36) and a JDK 17–21 installed.
Newer JDKs, such as the one bundled with current Android Studio, are not
supported. This installs both into your user profile; no admin rights needed:

    dotnet build PocketEncryptor.App -t:InstallAndroidDependencies -f net10.0-android ^
      -p:AndroidSdkDirectory="%LOCALAPPDATA%\Android\Sdk" ^
      -p:JavaSdkDirectory="%LOCALAPPDATA%\Android\openjdk" -p:AcceptAndroidSDKLicenses=True

The app project uses `%LOCALAPPDATA%\Android\openjdk` automatically when it
exists. Android Studio's emulators work for testing, including newer Android
versions than API 36.
