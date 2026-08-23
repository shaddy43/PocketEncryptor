# PocketEncryptor

A small personal CLI tool for encrypting and decrypting files with a passphrase,
using AES-256-GCM (authenticated encryption) and PBKDF2-HMAC-SHA256 key derivation.

## Usage

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

## Example

    dotnet run --project PocketEncryptor -- secret.docx secret.docx.enc -E
    dotnet run --project PocketEncryptor -- secret.docx.enc restored.docx -D
    dotnet run --project PocketEncryptor -- ./my_folder ./encrypted_folder -r
    --- OR
    PocketEncryptor.exe secret.docx secret.docx.enc -E

## Security notes

- AES-256-GCM provides confidentiality and integrity: a wrong passphrase or a
  tampered file is detected and rejected with a clear error, rather than
  silently producing garbage output.
- A random 16-byte salt and 12-byte nonce are generated for every encryption
  and stored (not secret) in the output file's header, so encrypting the same
  file twice with the same passphrase yields different ciphertext.
- The passphrase is passed through PBKDF2-HMAC-SHA256 with 600,000 iterations
  before being used as the AES key; it is entered interactively and never
  appears as a command-line argument, in shell history, or in `ps` output.
- This file format is NOT compatible with files produced by earlier versions
  of PocketEncryptor (which used a hard-coded zero IV and no salt/authentication).

## File format

    [4 bytes]  magic "PKEC"
    [1 byte]   format version (currently 0x01)
    [16 bytes] PBKDF2 salt
    [12 bytes] AES-GCM nonce
    [16 bytes] AES-GCM authentication tag
    [N bytes]  ciphertext (same length as the original plaintext)

## Requirements

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or newer.
  (Earlier versions targeted the now end-of-life .NET Core 3.1, which has no
  Apple Silicon build; the project targets `net8.0` so it runs natively on
  Windows, macOS — Intel and Apple Silicon — and Linux.)

## Building and testing

    dotnet build
    dotnet test          # runs the xUnit test suite

## Building on macOS

These steps work on both Apple Silicon (M1/M2/M3/M4) and Intel Macs.

1. **Install the .NET 8 SDK.** Pick one:

   - **Official installer (recommended):** download the macOS **SDK** for your
     chip — **Arm64** for Apple Silicon, **x64** for Intel — from
     <https://dotnet.microsoft.com/download/dotnet/8.0> and run the `.pkg`.
   - **Homebrew:** `brew install --cask dotnet-sdk`
   - **Install script (no admin, installs to `~/.dotnet`):**

         curl -fsSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0
         echo 'export PATH="$HOME/.dotnet:$PATH"' >> ~/.zshrc && source ~/.zshrc

   Open a new terminal and confirm the install (should print `8.0.x`, and the
   Architecture should match your chip — `arm64` on Apple Silicon):

       dotnet --version
       dotnet --info | grep -i arch

2. **Clone and enter the repo:**

       git clone https://github.com/shaddy43/PocketEncryptor.git
       cd PocketEncryptor

3. **Build and run the tests:**

       dotnet build
       dotnet test

4. **Run the tool:**

       echo "hello secret" > original.txt
       dotnet run --project PocketEncryptor -- original.txt encrypted.bin -E   # prompts for a passphrase
       dotnet run --project PocketEncryptor -- encrypted.bin restored.txt -D   # prompts for the passphrase
       diff original.txt restored.txt && echo "round-trip OK"

5. **(Optional) Produce a standalone binary** you can run without `dotnet run`
   — use `osx-arm64` on Apple Silicon, `osx-x64` on Intel:

       dotnet publish PocketEncryptor -c Release -r osx-arm64 --self-contained
       ./PocketEncryptor/bin/Release/net8.0/osx-arm64/publish/PocketEncryptor original.txt encrypted.bin -E

The masked passphrase prompt needs an interactive terminal (Terminal.app or
iTerm work fine); it will not work if standard input is redirected from a file
or pipe.
