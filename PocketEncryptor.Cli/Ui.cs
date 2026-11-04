using System.Reflection;
using System.Text;

namespace PocketEncryptor.Cli;

/// <summary>Everything the CLI prints: the banner, coloured messages and prompts.</summary>
/// <remarks>
/// Colours are the dark variants (DarkCyan, DarkGreen, …) so they read on both
/// dark and light terminal backgrounds. They're left out when the output is
/// redirected or NO_COLOR is set (https://no-color.org), and the banner is left
/// out when the output is redirected.
/// </remarks>
internal static class Ui
{
    private const ConsoleColor Accent = ConsoleColor.DarkCyan;
    private const ConsoleColor Muted = ConsoleColor.DarkGray;
    private const string Indent = "  ";

    private static bool s_color;

    public const string Author = "@shaddy43";

    /// <summary>"2.0", or "2.0.1" for a patch release.</summary>
    public static string Version
    {
        get
        {
            Version? v = Assembly.GetExecutingAssembly().GetName().Version;
            return v is null ? "?" : v.Build > 0 ? $"{v.Major}.{v.Minor}.{v.Build}" : $"{v.Major}.{v.Minor}";
        }
    }

    private static bool Interactive => !Console.IsOutputRedirected;

    public static void Init()
    {
        s_color = Interactive
            && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NO_COLOR"))
            && Environment.GetEnvironmentVariable("TERM") != "dumb";

        if (Interactive && OperatingSystem.IsWindows())
        {
            // UTF-16 makes .NET write to the console with WriteConsoleW, so the
            // banner's line drawing shows on every code page. Unlike UTF-8, it
            // doesn't change the console's code page for the commands that run
            // after this one.
            try
            {
                Console.OutputEncoding = Encoding.Unicode;
            }
            catch (IOException)
            {
                // Keep the default; at worst the banner shows '?' characters.
            }
        }
    }

    /// <summary>
    /// On macOS and Linux the terminal itself echoes keys until .NET's first
    /// console read turns that off, so a password typed before its prompt showed
    /// would appear in plain text. Checking for a key is such a read (it doesn't
    /// wait or take the key), and the terminal stays quiet until the program exits.
    /// Call it before anything else is printed.
    /// </summary>
    public static void HideTypedKeys()
    {
        if (Console.IsInputRedirected || OperatingSystem.IsWindows())
        {
            return;
        }
        try
        {
            _ = Console.KeyAvailable;
        }
        catch (InvalidOperationException)
        {
            // No terminal to set up.
        }
    }

    // ------------------------------------------------------------------
    // Banner and help
    // ------------------------------------------------------------------

    /// <summary>The padlock signature, shown at the start of every interactive run.</summary>
    public static void Banner()
    {
        if (!Interactive)
        {
            return;
        }

        const string text = "   "; // gap between the padlock and the text
        Console.WriteLine();
        Line(("     ┌───┐", Accent));
        Line(("     │   │", Accent), ("  " + text, null), ("Pocket", null), ("Encryptor", Accent), ("  v" + Version, Muted));
        Line(("   ┌─┴───┴─┐", Accent), (text, null), ("Lock any file with a password. Open it on any device.", null));
        Line(("   │   ●   │", Accent), (text, null), ("AES-256-GCM · Windows · macOS · Android · iPhone", Muted));
        Line(("   │   ▀   │", Accent));
        Line(("   └───────┘", Accent), (text, null), ("by ", Muted), (Author, Accent));
        Console.WriteLine();
    }

    /// <summary>The help text; every line fits in 80 columns.</summary>
    public static void Usage()
    {
        Heading("Usage");
        Row("Encrypt a file", "PocketEncryptor <file> <output> -E [--purge]");
        Row("Decrypt a file", "PocketEncryptor <file> <output> -D");
        Row("Encrypt a folder", "PocketEncryptor <folder> <output> -r [--purge]");
        Console.WriteLine();

        Heading("Options");
        Row("--purge", "delete the originals: once each encrypted copy is", left: null, right: Muted);
        Row("", "written and checked, the original is overwritten", left: null, right: Muted);
        Row("", "with random data and deleted. Asks first.", left: null, right: Muted);
        Row("-h, --help", "show this help", left: null, right: Muted);
        Row("--version", "show the version", left: null, right: Muted);
        Console.WriteLine();

        Heading("Examples");
        Line((Indent + Indent + "PocketEncryptor notes.txt notes.txt.pkec -E", null));
        Line((Indent + Indent + "PocketEncryptor notes.txt.pkec notes.txt -D", null));
        Line((Indent + Indent + "PocketEncryptor ./photos ./photos-encrypted -r --purge", null));
        Console.WriteLine();
        Line((Indent + "You're asked for the password; it's never on the command line.", Muted));
        Console.WriteLine();
    }

    private static void Heading(string text) => Line((Indent + text, Accent));

    /// <summary>A two-column help line: "    Encrypt a file        PocketEncryptor …".</summary>
    private static void Row(string label, string text, ConsoleColor? left = Muted, ConsoleColor? right = null) =>
        Line((Indent + Indent + label.PadRight(22), left), (text, right));

    // ------------------------------------------------------------------
    // Messages
    // ------------------------------------------------------------------

    public static void Info(string text) => Line((Indent + text, null));

    public static void Success(string text) => Line((Indent + text, ConsoleColor.DarkGreen));

    public static void Warning(string text) => Line((Indent + text, ConsoleColor.DarkYellow));

    public static void Error(string text) => Line((Indent + text, ConsoleColor.Red));

    /// <summary>One file of a folder run: "  Encrypted  photos/cat.jpg".</summary>
    public static void FileResult(string label, ConsoleColor color, string path, string? note = null)
    {
        Write(Indent + label.PadRight(11), color);
        Console.Write(path);
        if (note is not null)
        {
            Write(" (" + note + ")", Muted);
        }
        Console.WriteLine();
    }

    // ------------------------------------------------------------------
    // Prompts
    // ------------------------------------------------------------------

    /// <summary>Asks a yes/no question; anything but y or yes is no.</summary>
    public static bool Confirm(string question)
    {
        Write(Indent + question + " [y/N] ", ConsoleColor.DarkYellow);
        string answer = (Console.ReadLine() ?? string.Empty).Trim();
        return answer.Equals("y", StringComparison.OrdinalIgnoreCase)
            || answer.Equals("yes", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Reads a password without showing it: each character shows as '*'.</summary>
    public static string ReadPassword(string prompt)
    {
        Console.Write(Indent + prompt);
        var sb = new StringBuilder();
        while (true)
        {
            ConsoleKeyInfo keyInfo = Console.ReadKey(intercept: true);
            if (keyInfo.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            if (keyInfo.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0)
                {
                    sb.Remove(sb.Length - 1, 1);
                    Console.Write("\b \b");
                }
            }
            else if (!char.IsControl(keyInfo.KeyChar))
            {
                sb.Append(keyInfo.KeyChar);
                Console.Write('*');
            }
        }

        // .NET strings are immutable, so the password can't be reliably wiped
        // from memory. The keys made from it are (see PocketCrypto).
        return sb.ToString();
    }

    // ------------------------------------------------------------------

    private static void Line(params (string Text, ConsoleColor? Color)[] parts)
    {
        foreach ((string text, ConsoleColor? color) in parts)
        {
            if (color is { } c)
            {
                Write(text, c);
            }
            else
            {
                Console.Write(text);
            }
        }
        Console.WriteLine();
    }

    private static void Write(string text, ConsoleColor color)
    {
        if (!s_color)
        {
            Console.Write(text);
            return;
        }
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ResetColor();
    }
}
