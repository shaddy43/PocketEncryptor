using System.Security.Cryptography;
using PocketEncryptor.App.Services;
using PocketEncryptor.Core;

namespace PocketEncryptor.App;

public partial class MainPage : ContentPage
{
    private enum Mode { Encrypt, Decrypt }

    private enum StatusKind { Info, Success, Error }

    private const int RecommendedPasswordLength = 8;

    private Mode _mode = Mode.Encrypt;
    private FileResult? _file;
    private CancellationTokenSource? _cts;
    private bool _busy;

    public MainPage()
    {
        InitializeComponent();
        ApplyMode();
        ResetFile();

        if (!PocketCrypto.IsSupported)
        {
            ShowStatus(StatusKind.Error, "This device doesn't support AES-GCM encryption, so PocketEncryptor can't run here.");
            PickFileButton.IsEnabled = false;
        }
    }

    // ------------------------------------------------------------------
    // Mode
    // ------------------------------------------------------------------

    private void OnEncryptModeClicked(object? sender, EventArgs e) => SetMode(Mode.Encrypt);

    private void OnDecryptModeClicked(object? sender, EventArgs e) => SetMode(Mode.Decrypt);

    private void SetMode(Mode mode)
    {
        if (_busy || _mode == mode)
        {
            return;
        }
        _mode = mode;
        ConfirmEntry.Text = string.Empty;
        HideStatus();
        ApplyMode();
    }

    private void ApplyMode()
    {
        bool encrypt = _mode == Mode.Encrypt;
        StyleSegment(EncryptModeButton, selected: encrypt);
        StyleSegment(DecryptModeButton, selected: !encrypt);
        ConfirmEntry.IsVisible = encrypt;
        PasswordEntry.ReturnType = encrypt ? ReturnType.Next : ReturnType.Done;
        RunButton.Text = encrypt ? "Encrypt file" : "Decrypt file";
        UpdateState();
    }

    private static void StyleSegment(Button button, bool selected)
    {
        if (selected)
        {
            button.SetAppThemeColor(BackgroundColorProperty, Res("Primary"), Res("PrimaryDark"));
            button.SetAppThemeColor(Button.TextColorProperty, Colors.White, Res("PrimaryDarkText"));
        }
        else
        {
            button.SetAppThemeColor(BackgroundColorProperty, Res("Secondary"), Res("Gray900"));
            button.SetAppThemeColor(Button.TextColorProperty, Res("Primary"), Res("PrimaryDark"));
        }
        SemanticProperties.SetDescription(button, button.Text + (selected ? ", selected" : string.Empty));
    }

    // ------------------------------------------------------------------
    // File selection
    // ------------------------------------------------------------------

    private async void OnPickFileClicked(object? sender, EventArgs e)
    {
        try
        {
            FileResult? picked = await FilePicker.Default.PickAsync(new PickOptions { PickerTitle = "Choose a file" });
            if (picked is null)
            {
                return; // user cancelled
            }

            if (_file is not null && _file.FullPath != picked.FullPath)
            {
                WorkingFiles.DeletePickerCopy(_file);
            }
            _file = picked;
            HideStatus();
            FileNameLabel.Text = picked.FileName;

            // Pick the obvious mode: .pkec files get decrypted, anything else encrypted.
            bool encrypted = await LooksEncryptedAsync(picked);
            SetMode(encrypted ? Mode.Decrypt : Mode.Encrypt);
            FileInfoLabel.Text = encrypted ? "Encrypted file: enter its password to decrypt." : "Ready to encrypt.";
            UpdateState();
        }
        catch (Exception ex)
        {
            ShowStatus(StatusKind.Error, "Couldn't open that file: " + ex.Message);
        }
    }

    private static async Task<bool> LooksEncryptedAsync(FileResult file)
    {
        await using Stream stream = await file.OpenReadAsync();
        byte[] start = new byte[PkecFormat.Magic.Length];
        int read = await stream.ReadAtLeastAsync(start, start.Length, throwOnEndOfStream: false);
        return PkecFormat.HasMagic(start.AsSpan(0, read));
    }

    private void ResetFile()
    {
        _file = null;
        FileNameLabel.Text = "No file chosen";
        FileInfoLabel.Text = "Pick any file to encrypt, or a .pkec file to decrypt.";
        UpdateState();
    }

    // ------------------------------------------------------------------
    // Password
    // ------------------------------------------------------------------

    private void OnPasswordTextChanged(object? sender, TextChangedEventArgs e) => UpdateState();

    private void OnPasswordCompleted(object? sender, EventArgs e)
    {
        if (_mode == Mode.Encrypt)
        {
            ConfirmEntry.Focus();
        }
        else
        {
            TryRun();
        }
    }

    private void OnConfirmCompleted(object? sender, EventArgs e) => TryRun();

    private void OnShowPasswordChanged(object? sender, CheckedChangedEventArgs e)
    {
        PasswordEntry.IsPassword = !e.Value;
        ConfirmEntry.IsPassword = !e.Value;
    }

    private void OnShowPasswordLabelTapped(object? sender, TappedEventArgs e) =>
        ShowPasswordCheckBox.IsChecked = !ShowPasswordCheckBox.IsChecked;

    private void ClearPasswords()
    {
        PasswordEntry.Text = string.Empty;
        ConfirmEntry.Text = string.Empty;
        ShowPasswordCheckBox.IsChecked = false;
    }

    // Enables the Run button only when the input is complete, and explains why not.
    private void UpdateState()
    {
        string password = PasswordEntry.Text ?? string.Empty;
        string confirm = ConfirmEntry.Text ?? string.Empty;

        string? hint = null;
        bool hintIsError = false;
        bool passwordOk = password.Length > 0;

        if (_mode == Mode.Encrypt && password.Length > 0)
        {
            if (confirm.Length > 0 && confirm != password)
            {
                hint = "Passwords don't match.";
                hintIsError = true;
            }
            else if (password.Length < RecommendedPasswordLength)
            {
                hint = $"Tip: use at least {RecommendedPasswordLength} characters. Longer passwords are much harder to guess.";
            }
            passwordOk = confirm == password;
        }

        PasswordHintLabel.IsVisible = hint is not null;
        PasswordHintLabel.Text = hint;
        PasswordHintLabel.SetAppThemeColor(Label.TextColorProperty,
            hintIsError ? Res("ErrorLight") : Res("Gray500"),
            hintIsError ? Res("ErrorDark") : Res("Gray400"));

        RunButton.IsEnabled = !_busy && _file is not null && passwordOk;
        PickFileButton.IsEnabled = !_busy && PocketCrypto.IsSupported;
        EncryptModeButton.IsEnabled = !_busy;
        DecryptModeButton.IsEnabled = !_busy;
        PasswordEntry.IsEnabled = !_busy;
        ConfirmEntry.IsEnabled = !_busy;
    }

    // ------------------------------------------------------------------
    // Encrypt / decrypt
    // ------------------------------------------------------------------

    private void TryRun()
    {
        if (RunButton.IsEnabled)
        {
            OnRunClicked(RunButton, EventArgs.Empty);
        }
    }

    private void OnCancelClicked(object? sender, EventArgs e) => _cts?.Cancel();

    private async void OnRunClicked(object? sender, EventArgs e)
    {
        if (_busy || _file is null)
        {
            return;
        }

        FileResult file = _file;
        Mode mode = _mode;
        string password = PasswordEntry.Text ?? string.Empty;
        string tempPath = WorkingFiles.NewTempPath();
        using var cts = new CancellationTokenSource();
        _cts = cts;
        CancellationToken ct = cts.Token;

        SetBusy(true, mode == Mode.Encrypt ? "Encrypting…" : "Decrypting…");
        try
        {
            // 1. Produce the full result in private temp storage. For decryption
            //    this means the whole file has authenticated before we save it.
            await using (Stream input = await file.OpenReadAsync())
            {
                long total = TryGetLength(input);
                WorkProgress.Progress = 0;
                var progress = new ThrottledProgress(done =>
                {
                    if (total > 0)
                    {
                        WorkProgress.Progress = Math.Min(1.0, done / (double)total);
                    }
                });

                await Task.Run(() =>
                {
                    using var output = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920);
                    if (mode == Mode.Encrypt)
                    {
                        PocketCrypto.Encrypt(input, output, password, progress: progress, cancellationToken: ct);
                    }
                    else
                    {
                        PocketCrypto.Decrypt(input, output, password, progress, ct);
                    }
                }, ct);
            }
            WorkProgress.Progress = 1;

            // 2. Let the user choose where it goes (native Save dialog).
            BusyLabel.Text = "Choose where to save…";
            string? savedPath = await OutputSaver.SaveAsync(
                tempPath, SuggestOutputName(file.FileName, mode), file.FullPath, ct);

            if (savedPath is not null)
            {
                string verb = mode == Mode.Encrypt ? "Encrypted" : "Decrypted";
                ShowStatus(StatusKind.Success, $"{verb} \"{file.FileName}\".\nSaved to: {savedPath}");
                ClearPasswords();
                WorkingFiles.DeletePickerCopy(file);
                ResetFile();
            }
            else
            {
                ShowStatus(StatusKind.Info, "Not saved. Press the button again when you're ready to save.");
            }
        }
        catch (SaveRefusedException ex)
        {
            ShowStatus(StatusKind.Error, ex.Message);
        }
        catch (CryptographicException)
        {
            ShowStatus(StatusKind.Error, "Wrong password, or the file is damaged or has been tampered with.");
        }
        catch (InvalidDataException ex)
        {
            ShowStatus(StatusKind.Error, ex.Message);
        }
        catch (OperationCanceledException)
        {
            ShowStatus(StatusKind.Info, "Cancelled.");
        }
        catch (Exception ex)
        {
            ShowStatus(StatusKind.Error, "Something went wrong: " + ex.Message);
        }
        finally
        {
            WorkingFiles.TryDelete(tempPath);
            _cts = null;
            SetBusy(false);
        }
    }

    private static long TryGetLength(Stream stream)
    {
        try
        {
            return stream.CanSeek ? stream.Length : -1;
        }
        catch (NotSupportedException)
        {
            return -1;
        }
    }

    /// <summary>"photo.jpg" → "photo.jpg.pkec" and back; anything else → "name.decrypted".</summary>
    private static string SuggestOutputName(string fileName, Mode mode)
    {
        if (mode == Mode.Encrypt)
        {
            return fileName + PkecFormat.FileExtension;
        }
        foreach (string extension in new[] { PkecFormat.FileExtension, ".enc" })
        {
            if (fileName.Length > extension.Length && fileName.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
            {
                return fileName[..^extension.Length];
            }
        }
        return fileName + ".decrypted";
    }

    // ------------------------------------------------------------------
    // UI state helpers
    // ------------------------------------------------------------------

    private void SetBusy(bool busy, string? message = null)
    {
        _busy = busy;
        BusyPanel.IsVisible = busy;
        BusySpinner.IsRunning = busy;
        BusyLabel.Text = message;
        if (busy)
        {
            HideStatus();
        }
        UpdateState();
    }

    private void ShowStatus(StatusKind kind, string message)
    {
        StatusLabel.Text = message;
        (string bgLight, string bgDark, string fgLight, string fgDark) = kind switch
        {
            StatusKind.Success => ("Secondary", "Tertiary", "MidnightBlue", "White"),
            StatusKind.Error => ("ErrorBackgroundLight", "ErrorBackgroundDark", "ErrorLight", "ErrorDark"),
            _ => ("Gray100", "Gray900", "Gray900", "Gray100"),
        };
        StatusBorder.SetAppThemeColor(BackgroundColorProperty, Res(bgLight), Res(bgDark));
        StatusLabel.SetAppThemeColor(Label.TextColorProperty, Res(fgLight), Res(fgDark));
        StatusBorder.IsVisible = true;
        SemanticScreenReader.Announce(message);
    }

    private void HideStatus() => StatusBorder.IsVisible = false;

    private static Color Res(string key) =>
        Application.Current?.Resources.TryGetValue(key, out object? value) == true && value is Color color
            ? color
            : Colors.Gray;
}
