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

## Building and testing

    dotnet build
    dotnet test
