using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using PocketEncryptor.Core;

namespace PocketEncryptor.Cli;

public static class Program
{
    private enum Mode { Encrypt, Decrypt, EncryptFolder }

    private sealed record Options(Mode Mode, string Input, string Output, bool Purge);

    public static int Main(string[] args)
    {
        Ui.Init();

        if (args.Contains("--version"))
        {
            Console.WriteLine("PocketEncryptor " + Ui.Version);
            return 0;
        }

        Ui.HideTypedKeys();
        Ui.Banner();
        if (args.Length == 0 || args.Any(a => a is "-h" or "--help" or "-?" or "/?"))
        {
            Ui.Usage();
            return args.Length == 0 ? 1 : 0;
        }

        if (!TryParse(args, out Options? options, out string? problem))
        {
            Ui.Error(problem);
            Console.WriteLine();
            Ui.Usage();
            return 1;
        }

        if (Console.IsInputRedirected)
        {
            // Console.ReadKey needs a terminal: the password is never read from a pipe.
            Ui.Error("The password has to be typed in a terminal; input can't be redirected.");
            return 1;
        }

        try
        {
            return options.Mode switch
            {
                Mode.Encrypt => RunEncrypt(options),
                Mode.Decrypt => RunDecrypt(options),
                _ => RunEncryptFolder(options),
            };
        }
        catch (Exception ex)
        {
            return ReportError(ex);
        }
    }

    /// <summary>
    /// "&lt;input&gt; &lt;output&gt; -E|-D|-r [--purge]". The mode and --purge may
    /// come anywhere; the two paths keep their order.
    /// </summary>
    private static bool TryParse(string[] args, [NotNullWhen(true)] out Options? options,
        [NotNullWhen(false)] out string? problem)
    {
        options = null;
        Mode? mode = null;
        bool purge = false;
        var paths = new List<string>();

        foreach (string arg in args)
        {
            Mode? flag = arg switch
            {
                "-E" => Mode.Encrypt,
                "-D" => Mode.Decrypt,
                "-r" => Mode.EncryptFolder,
                _ => null,
            };
            if (flag is not null)
            {
                if (mode is not null && mode != flag)
                {
                    problem = "Choose one of -E, -D or -r.";
                    return false;
                }
                mode = flag;
            }
            else if (arg == "--purge")
            {
                purge = true;
            }
            else if (arg.Length > 1 && arg[0] == '-')
            {
                problem = $"Unknown option: {arg}";
                return false;
            }
            else
            {
                paths.Add(arg);
            }
        }

        if (mode is null)
        {
            problem = "Add -E to encrypt, -D to decrypt or -r to encrypt a folder.";
            return false;
        }
        if (paths.Count != 2)
        {
            problem = paths.Count < 2 ? "Give an input and an output." : "Too many paths: give one input and one output.";
            return false;
        }
        if (purge && mode == Mode.Decrypt)
        {
            problem = "--purge works only when encrypting (-E or -r).";
            return false;
        }

        options = new Options(mode.Value, paths[0], paths[1], purge);
        problem = null;
        return true;
    }

    // ------------------------------------------------------------------
    // Modes
    // ------------------------------------------------------------------

    private static int RunEncrypt(Options o)
    {
        if (o.Purge)
        {
            if (!File.Exists(o.Input))
            {
                Ui.Error("File not found: " + o.Input);
                return 1;
            }
            if (SamePath(o.Input, o.Output))
            {
                Ui.Error("With --purge, the output must be a different file from the input.");
                return 1;
            }
            Ui.Warning($"Purge: once {o.Output} is written and checked,");
            Ui.Warning($"{o.Input} is overwritten with random data and deleted.");
            Ui.Warning("Without the password, it can't be recovered.");
            if (!Ui.Confirm("Delete the original?"))
            {
                Ui.Info("Cancelled. Nothing was changed.");
                return 1;
            }
            Console.WriteLine();
        }

        string? password = ReadNewPassword();
        if (password is null)
        {
            return 1;
        }

        Ui.Info("Encrypting " + o.Input + " ...");
        PocketCrypto.EncryptFile(o.Input, o.Output, password);

        if (!o.Purge)
        {
            Ui.Success("Encrypted: " + o.Output);
            return 0;
        }

        Ui.Info("Checking " + o.Output + " ...");
        string? whyKept = Purge(o.Input, o.Output, password, out bool copyRemoved);
        if (copyRemoved)
        {
            Ui.Error("The encrypted copy didn't check out, so it was removed and the original kept.");
            return 1;
        }
        if (whyKept is not null)
        {
            Ui.Warning("Encrypted: " + o.Output);
            Ui.Warning("The original was kept: " + whyKept);
            return 1;
        }
        Ui.Success("Encrypted: " + o.Output);
        Ui.Success("Original overwritten and deleted: " + o.Input);
        return 0;
    }

    private static int RunDecrypt(Options o)
    {
        string password = Ui.ReadPassword("Password: ");

        Ui.Info("Decrypting " + o.Input + " ...");
        // DecryptFile only writes the output once the whole file has
        // authenticated, so a failure never leaves a broken file behind.
        PocketCrypto.DecryptFile(o.Input, o.Output, password);
        Ui.Success("Decrypted: " + o.Output);
        return 0;
    }

    private static int RunEncryptFolder(Options o)
    {
        if (!Directory.Exists(o.Input))
        {
            Ui.Error("Folder not found: " + o.Input);
            return 1;
        }
        string inputDir = Path.GetFullPath(o.Input);

        if (o.Purge)
        {
            Ui.Warning("Purge: once each encrypted copy is written and checked, its original");
            Ui.Warning("in " + inputDir + " is overwritten with random data and deleted.");
            Ui.Warning("Without the password, they can't be recovered.");
            if (!Ui.Confirm("Delete the originals?"))
            {
                Ui.Info("Cancelled. Nothing was changed.");
                return 1;
            }
            Console.WriteLine();
        }

        string? password = ReadNewPassword();
        if (password is null)
        {
            return 1;
        }

        Ui.Info("Encrypting every file in " + inputDir);
        Console.WriteLine();
        int encrypted = 0, replaced = 0, kept = 0, failed = 0;
        DirectoryEncryptor.EncryptDirectory(o.Input, o.Output, password, onFile: result =>
        {
            if (!result.Succeeded)
            {
                failed++;
                Ui.FileResult("Failed", ConsoleColor.Red, result.RelativePath, Describe(result.Error!));
                return;
            }
            if (!o.Purge)
            {
                encrypted++;
                Ui.FileResult("Encrypted", ConsoleColor.DarkGreen, result.RelativePath);
                return;
            }

            string? whyKept = Purge(result.SourcePath, result.OutputPath, password, out bool copyRemoved);
            if (copyRemoved)
            {
                failed++;
                Ui.FileResult("Failed", ConsoleColor.Red, result.RelativePath,
                    "the encrypted copy didn't check out, so it was removed and the original kept");
            }
            else if (whyKept is not null)
            {
                encrypted++;
                kept++;
                Ui.FileResult("Kept", ConsoleColor.DarkYellow, result.RelativePath,
                    "encrypted, but the original couldn't be deleted: " + whyKept);
            }
            else
            {
                encrypted++;
                replaced++;
                Ui.FileResult("Replaced", ConsoleColor.DarkGreen, result.RelativePath);
            }
        });

        Console.WriteLine();
        string summary = $"Done: {encrypted} encrypted, {failed} failed.";
        if (o.Purge)
        {
            summary += $" {replaced} original(s) deleted, {kept} kept.";
        }
        if (failed == 0 && kept == 0)
        {
            Ui.Success(summary);
            return 0;
        }
        Ui.Warning(summary);
        return 1;
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// <summary>
    /// Purge one file: check that <paramref name="copy"/> decrypts in full, then
    /// overwrite and delete <paramref name="original"/>. Returns null when the
    /// original is gone, or why it was kept.
    /// </summary>
    /// <param name="copyRemoved">
    /// True when the copy didn't decrypt: it's deleted and the original kept.
    /// </param>
    private static string? Purge(string original, string copy, string password, out bool copyRemoved)
    {
        copyRemoved = false;
        try
        {
            PocketCrypto.VerifyFile(copy, password);
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidDataException or IOException
            or UnauthorizedAccessException)
        {
            try
            {
                File.Delete(copy);
            }
            catch (Exception deleteError) when (deleteError is IOException or UnauthorizedAccessException)
            {
                // Best effort; the original is kept either way.
            }
            copyRemoved = true;
            return "the encrypted copy didn't check out";
        }

        try
        {
            SecureFile.OverwriteAndDelete(original);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ex.Message;
        }
    }

    private static bool SamePath(string a, string b) =>
        string.Equals(Path.GetFullPath(a), Path.GetFullPath(b),
            OperatingSystem.IsLinux() ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);

    /// <summary>Asks twice to catch typos. Null after three mismatches.</summary>
    private static string? ReadNewPassword()
    {
        const int Attempts = 3;
        for (int attempt = 1; attempt <= Attempts; attempt++)
        {
            string first = Ui.ReadPassword("Password: ");
            string second = Ui.ReadPassword("Confirm:  ");
            if (first == second)
            {
                return first;
            }
            if (attempt < Attempts)
            {
                Ui.Warning("The passwords don't match. Try again.");
            }
        }
        Ui.Error("Stopped: the passwords didn't match. Nothing was changed.");
        return null;
    }

    private static string Describe(Exception ex) => ex switch
    {
        CryptographicException => "wrong password, or the file is damaged",
        _ => ex.Message,
    };

    private static int ReportError(Exception ex)
    {
        switch (ex)
        {
            case CryptographicException:
                // AES-GCM tag mismatch: wrong password or a changed/damaged file.
                Ui.Error("Wrong password, or the file is damaged. Nothing was written.");
                break;
            case InvalidDataException:
                // Header validation messages are already user-facing.
                Ui.Error(ex.Message);
                break;
            case PlatformNotSupportedException:
                Ui.Error("Not supported: " + ex.Message);
                break;
            case UnauthorizedAccessException:
            case IOException:
                Ui.Error("File error: " + ex.Message);
                break;
            default:
                Ui.Error("Unexpected error: " + ex.Message);
                break;
        }

        // Debugging escape hatch: full details only when explicitly requested.
        if (Environment.GetEnvironmentVariable("POCKETENCRYPTOR_DEBUG") == "1")
        {
            Console.WriteLine(ex.ToString());
        }

        return 1;
    }
}
