using System.Collections.ObjectModel;
using System.Security.Cryptography;
using PocketEncryptor.App.Models;
using PocketEncryptor.App.Services;
using PocketEncryptor.Core;

namespace PocketEncryptor.App;

public partial class MainPage : ContentPage
{
    private enum Mode { Encrypt, Decrypt }

    private enum StatusKind { Info, Success, Error }

    private const int RecommendedPasswordLength = 8;
    private const string WrongPasswordMessage = "Wrong password, or the file is damaged or has been tampered with.";

    private readonly ObservableCollection<SelectedFile> _files = [];
    private Mode _mode = Mode.Encrypt;
    private CancellationTokenSource? _cts;
    private bool _busy;

    public MainPage()
    {
        InitializeComponent();
        BindableLayout.SetItemsSource(FileList, _files);
        ApplyMode();
        ShowFiles();

        if (!PocketCrypto.IsSupported)
        {
            ShowStatus(StatusKind.Error, "This device doesn't support AES-GCM encryption, so PocketEncryptor can't run here.");
            PickFileButton.IsEnabled = false;
            return;
        }

        IncomingFiles.Changed += ProcessIncoming;
#if WINDOWS
        AddDropTarget();
#endif
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        ProcessIncoming(); // files shared or opened before the page existed
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
        ReplacePanel.IsVisible = encrypt && CanRemoveOriginals;
        if (!encrypt)
        {
            ReplaceCheckBox.IsChecked = false;
        }
        RefreshFileStatuses();
        UpdateState();
    }

    // ------------------------------------------------------------------
    // Delete originals after encrypting
    // ------------------------------------------------------------------

    /// <summary>Platforms where the app gets to delete originals (iOS/macOS: still to come).</summary>
#if WINDOWS || ANDROID
    private const bool CanRemoveOriginals = true;
#else
    private const bool CanRemoveOriginals = false;
#endif

    private bool RemoveOriginals => _mode == Mode.Encrypt && ReplaceCheckBox.IsChecked;

    private void OnReplaceLabelTapped(object? sender, TappedEventArgs e) =>
        ReplaceCheckBox.IsChecked = !ReplaceCheckBox.IsChecked;

    private void OnReplaceChanged(object? sender, CheckedChangedEventArgs e)
    {
        ReplaceWarningLabel.IsVisible = e.Value;
        ReplaceWarningLabel.Text = OperatingSystem.IsWindows()
            ? "Each encrypted file is saved next to its original and checked, then the original is overwritten and deleted. Only your password can bring it back."
            : "Each encrypted file is saved where you choose and checked, then the original is overwritten and deleted. Only your password can bring it back.";
        UpdateState();
    }

    /// <summary>Asks before a run that deletes originals. False: don't run.</summary>
    private async Task<bool> ConfirmRemovingOriginalsAsync(List<SelectedFile> targets)
    {
        int removable = targets.Count(f => f.Original is { WhyNotRemovable: null });
        if (removable == 0)
        {
            ShowStatus(StatusKind.Info, (targets.Count == 1 ? "The app can't delete this original" : "The app can't delete these originals")
                + " (shared from another app, read-only, or stored where deleting isn't allowed). "
                + "Untick \"Delete originals after encrypting\" to just encrypt.");
            return false;
        }

        string which = removable == targets.Count
            ? removable switch { 1 => "the original", 2 => "both originals", _ => $"all {removable} originals" }
            : $"{removable} of the {targets.Count} originals (the rest can't be deleted here and will be kept)";
        string message =
            $"Once each encrypted copy is saved and checked, {which} will be overwritten and deleted. "
            + "Without the password, they can't be recovered.\n\n"
            + "Copies elsewhere aren't touched: backups, cloud sync, the Recycle Bin or trash, and traces that SSDs and "
            + "phones keep internally. Full-disk encryption is what protects those.";
        return await DisplayAlertAsync("Delete the originals?", message, "Encrypt and delete", "Cancel");
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

    private bool IsBatch => _files.Count > 1;

    /// <summary>
    /// The files the Run button will process. With several files, each mode
    /// only takes the files it applies to (encrypt: not yet encrypted;
    /// decrypt: encrypted), so a mixed selection can be handled in two runs.
    /// </summary>
    private List<SelectedFile> RunnableFiles() =>
        _files.Where(f => f.State != FileState.Done && (!IsBatch || f.IsEncrypted == (_mode == Mode.Decrypt))).ToList();

    private async void OnPickFileClicked(object? sender, EventArgs e)
    {
        IReadOnlyList<PickedFile> picked;
        try
        {
            picked = await InputPicker.PickFilesAsync();
        }
        catch (Exception ex)
        {
            ShowStatus(StatusKind.Error, "Couldn't open the file picker: " + Describe(ex));
            return;
        }
        if (picked.Count > 0)
        {
            await LoadFilesAsync(picked);
        }
    }

    /// <summary>Replaces the selection with these files (picked, shared, opened or dropped).</summary>
    private async Task LoadFilesAsync(IReadOnlyList<PickedFile> files)
    {
        var loaded = new List<SelectedFile>(files.Count);
        try
        {
            foreach (PickedFile file in files)
            {
                loaded.Add(await SelectedFile.LoadAsync(file));
            }
        }
        catch (Exception ex)
        {
            foreach (PickedFile file in files)
            {
                WorkingFiles.DeletePickerCopy(file.File);
            }
            ShowStatus(StatusKind.Error, "Couldn't open that file: " + Describe(ex));
            return;
        }

        ClearFiles(keep: files);
        foreach (SelectedFile file in loaded)
        {
            _files.Add(file);
        }
        HideStatus();

        // Pick the obvious mode: encrypted files get decrypted, anything else encrypted.
        SetMode(loaded.All(f => f.IsEncrypted) ? Mode.Decrypt : Mode.Encrypt);
        RefreshFileStatuses();
        ShowFiles();
        UpdateState();
    }

    /// <summary>
    /// Loads files handed to the app from outside (see IncomingFiles). While a
    /// run is in progress they wait, and are loaded when it finishes.
    /// </summary>
    private async void ProcessIncoming()
    {
        if (_busy)
        {
            return;
        }
        IReadOnlyList<PickedFile>? files = IncomingFiles.TakeFiles();
        IncomingNotice? notice = IncomingFiles.TakeNotice();
        if (files is not null)
        {
            await LoadFilesAsync(files);
        }
        if (notice is not null)
        {
            ShowStatus(notice.IsError ? StatusKind.Error : StatusKind.Info, notice.Text);
        }
    }

#if WINDOWS
    private Brush? _normalStroke;

    /// <summary>Accepts files dragged onto the window, e.g. from File Explorer.</summary>
    private void AddDropTarget()
    {
        _normalStroke = FilesBorder.Stroke;
        var drop = new DropGestureRecognizer { AllowDrop = true };
        drop.DragOver += (_, e) =>
        {
            if (_busy)
            {
                return;
            }
            e.AcceptedOperation = DataPackageOperation.Copy;
            if (e.PlatformArgs?.DragEventArgs is { } args)
            {
                args.AcceptedOperation = global::Windows.ApplicationModel.DataTransfer.DataPackageOperation.Copy;
                args.DragUIOverride.Caption = "Add to PocketEncryptor";
            }
            FilesBorder.Stroke = new SolidColorBrush(Res("Primary"));
        };
        drop.DragLeave += (_, _) => FilesBorder.Stroke = _normalStroke;
        drop.Drop += OnDrop;
        PageScroll.GestureRecognizers.Add(drop);
    }

    private async void OnDrop(object? sender, DropEventArgs e)
    {
        FilesBorder.Stroke = _normalStroke;
        if (_busy || e.PlatformArgs?.DragEventArgs.DataView is not { } data
            || !data.Contains(global::Windows.ApplicationModel.DataTransfer.StandardDataFormats.StorageItems))
        {
            return;
        }
        e.Handled = true;

        var items = await data.GetStorageItemsAsync();
        List<PickedFile> files = [.. items.OfType<global::Windows.Storage.StorageFile>()
            .Where(f => !string.IsNullOrEmpty(f.Path))
            .Select(f => PickedFile.FromPath(f.Path))];
        bool hadFolders = items.Any(i => i is global::Windows.Storage.IStorageFolder);

        if (files.Count > 0)
        {
            await LoadFilesAsync(files);
        }
        if (hadFolders)
        {
            ShowStatus(StatusKind.Info, files.Count > 0
                ? "Folders were left out: only files can be added."
                : "Folders can't be added yet. Drop the files inside them instead.");
        }
    }
#endif

    private static string Describe(Exception ex) =>
        string.IsNullOrWhiteSpace(ex.Message) ? $"{ex.GetType().Name} (0x{ex.HResult:X8})" : ex.Message;

    /// <summary>Forgets the chosen files, deleting any private copies the picker made.</summary>
    private void ClearFiles(IReadOnlyCollection<PickedFile>? keep = null)
    {
        foreach (SelectedFile file in _files)
        {
            if (keep is null || !keep.Any(k => k.File.FullPath == file.Source.FullPath))
            {
                WorkingFiles.DeletePickerCopy(file.Source);
            }
        }
        _files.Clear();
        ShowFiles();
        UpdateState();
    }

    private void ShowFiles()
    {
        int count = _files.Count;
        FileList.IsVisible = count > 1;

        if (count == 0)
        {
            FileNameLabel.Text = "No files chosen";
            FileInfoLabel.Text = "Pick files to encrypt, or .pkec files to decrypt.";
            return;
        }
        if (count == 1)
        {
            FileNameLabel.Text = _files[0].Name;
            FileInfoLabel.Text = _files[0].IsEncrypted ? "Encrypted file: enter its password to decrypt." : "Ready to encrypt.";
            return;
        }

        int encrypted = _files.Count(f => f.IsEncrypted);
        string size = SelectedFile.FormatSize(_files.Sum(f => Math.Max(0, f.Size)));
        FileNameLabel.Text = $"{count} files";
        FileInfoLabel.Text =
            encrypted == 0 ? $"{size} in total. Ready to encrypt."
            : encrypted == count ? $"Encrypted files, {size} in total: enter their password to decrypt."
            : $"{encrypted} encrypted, {count - encrypted} not. Each mode skips the files it doesn't apply to.";
    }

    /// <summary>Resets the per-file lines of files not yet done to suit the current mode.</summary>
    private void RefreshFileStatuses()
    {
        foreach (SelectedFile file in _files.Where(f => f.State != FileState.Done))
        {
            string size = SelectedFile.FormatSize(file.Size);
            if (_mode == Mode.Encrypt)
            {
                file.Update(file.IsEncrypted ? FileState.Skipped : FileState.Pending,
                    file.IsEncrypted ? "Already encrypted: skipped when encrypting" : size);
            }
            else
            {
                file.Update(file.IsEncrypted ? FileState.Pending : FileState.Skipped,
                    file.IsEncrypted ? "Encrypted · " + size : "Not encrypted: skipped when decrypting");
            }
        }
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

        int runnable = RunnableFiles().Count;
        string verb = _mode == Mode.Encrypt ? "Encrypt" : "Decrypt";
        if (RemoveOriginals)
        {
            RunButton.Text = runnable <= 1 ? "Encrypt, delete original" : $"Encrypt {runnable}, delete originals";
            RunButton.SetAppThemeColor(BackgroundColorProperty, Res("ErrorLight"), Res("ErrorDark"));
        }
        else
        {
            RunButton.Text = runnable <= 1 ? $"{verb} file" : $"{verb} {runnable} files";
            RunButton.ClearValue(BackgroundColorProperty); // back to the style's color
        }

        RunButton.IsEnabled = !_busy && runnable > 0 && passwordOk;
        ReplaceCheckBox.IsEnabled = !_busy;
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
        List<SelectedFile> targets = RunnableFiles();
        if (_busy || targets.Count == 0)
        {
            return;
        }

        Mode mode = _mode;
        bool removeOriginals = RemoveOriginals;
        if (removeOriginals && !await ConfirmRemovingOriginalsAsync(targets))
        {
            return;
        }

        string password = PasswordEntry.Text ?? string.Empty;
        using var cts = new CancellationTokenSource();
        _cts = cts;

        SetBusy(true, mode == Mode.Encrypt ? "Encrypting…" : "Decrypting…");
        try
        {
            if (IsBatch || removeOriginals)
            {
                await RunBatchAsync(targets, mode, password, removeOriginals, cts.Token);
            }
            else
            {
                await RunSingleAsync(targets[0], mode, password, cts.Token);
            }
        }
        finally
        {
            _cts = null;
            if (removeOriginals)
            {
                ReplaceCheckBox.IsChecked = false; // destructive runs are opt-in every time
            }
            SetBusy(false);
        }
        ProcessIncoming(); // anything shared while busy
    }

    /// <summary>One file: process it, then a Save dialog with the suggested name.</summary>
    private async Task RunSingleAsync(SelectedFile file, Mode mode, string password, CancellationToken ct)
    {
        string? tempPath = null;
        try
        {
            // 1. Produce the full result in private temp storage. For decryption
            //    this means the whole file has authenticated before we save it.
            tempPath = await ProcessToTempAsync(file, mode, password, done => SetProgress(done, file.Size), ct);

            // 2. Let the user choose where it goes (native Save dialog).
            BusyLabel.Text = "Choose where to save…";
            string? savedPath = await OutputSaver.SaveAsync(tempPath, OutputName(file.Name, mode), file.Source.FullPath, ct);
            if (savedPath is null)
            {
                ShowStatus(StatusKind.Info, "Not saved. Press the button again when you're ready to save.");
                return;
            }

            string verb = mode == Mode.Encrypt ? "Encrypted" : "Decrypted";
            ShowStatus(StatusKind.Success, $"{verb} \"{file.Name}\".\nSaved to: {savedPath}");
            ClearPasswords();
            ClearFiles();
        }
        catch (SaveRefusedException ex)
        {
            ShowStatus(StatusKind.Error, ex.Message);
        }
        catch (CryptographicException)
        {
            ShowStatus(StatusKind.Error, WrongPasswordMessage);
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
        }
    }

    /// <summary>
    /// Several files (or deleting originals): ask for a folder once, then
    /// process and save each file in turn. One file failing (e.g. a different
    /// password) doesn't stop the rest.
    /// </summary>
    /// <param name="removeOriginals">
    /// After each encrypted file is saved, read it back and check it decrypts,
    /// then overwrite and delete the original. On Windows the encrypted file
    /// goes right next to the original, so no folder is asked for.
    /// </param>
    private async Task RunBatchAsync(List<SelectedFile> targets, Mode mode, string password, bool removeOriginals,
        CancellationToken ct)
    {
        IOutputFolder? NextToOriginal(SelectedFile f) => removeOriginals ? OutputSaver.FolderOfOriginal(f.Original) : null;

        IOutputFolder? chosen = null;
        if (targets.Any(f => NextToOriginal(f) is null))
        {
            BusyLabel.Text = removeOriginals ? "Choose where to save the encrypted files…" : "Choose a folder for the results…";
            try
            {
                chosen = await OutputSaver.PickFolderAsync(ct);
            }
            catch (OperationCanceledException)
            {
                ShowStatus(StatusKind.Info, "Cancelled.");
                return;
            }
            catch (Exception ex)
            {
                ShowStatus(StatusKind.Error, ex is SaveRefusedException ? ex.Message : "Can't use that folder: " + ex.Message);
                return;
            }
            if (chosen is null)
            {
                ShowStatus(StatusKind.Info, "No folder chosen, so nothing was saved.");
                return;
            }
        }

        string verb = mode == Mode.Encrypt ? "Encrypting" : "Decrypting";
        long total = targets.Sum(f => Math.Max(0, f.Size));
        long finished = 0;
        int savedCount = 0, failed = 0, notSaved = 0, removed = 0, kept = 0;
        bool cancelled = false;

        for (int i = 0; i < targets.Count && !cancelled; i++)
        {
            SelectedFile file = targets[i];
            BusyLabel.Text = $"{verb} {i + 1} of {targets.Count}: {file.Name}";
            file.Update(FileState.Working, verb + "…");
            long before = finished;
            string? tempPath = null;
            try
            {
                tempPath = await ProcessToTempAsync(file, mode, password, done => SetProgress(before + done, total), ct);
                IOutputFolder folder = NextToOriginal(file) ?? chosen!;
                SavedOutput? saved = await folder.SaveAsync(tempPath, OutputName(file.Name, mode), ct);
                if (saved is null)
                {
                    file.Update(FileState.Pending, "Not saved");
                    notSaved++;
                    continue;
                }
                savedCount++;

                if (!removeOriginals)
                {
                    file.Update(FileState.Done, "Saved as " + saved.Name);
                    WorkingFiles.DeletePickerCopy(file.Source);
                    continue;
                }

                string? whyKept = file.Original is null ? "it was shared from another app" : file.Original.WhyNotRemovable;
                if (whyKept is null)
                {
                    // Never delete an original unless its encrypted copy, as saved,
                    // decrypts with this password.
                    BusyLabel.Text = $"Checking {saved.Name}…";
                    if (!await SavedCopyDecryptsAsync(saved, password, ct))
                    {
                        saved.Delete();
                        savedCount--;
                        file.Update(FileState.Failed, "The saved copy didn't check out, so it was removed and the original kept");
                        failed++;
                        continue;
                    }

                    ct.ThrowIfCancellationRequested(); // last point to stop before deleting
                    BusyLabel.Text = $"Deleting the original of {file.Name}…";
                    try
                    {
                        await file.Original!.RemoveAsync();
                    }
                    catch (Exception ex)
                    {
                        whyKept = "couldn't delete it: " + Describe(ex);
                    }
                }

                if (whyKept is null)
                {
                    file.Update(FileState.Done, $"Replaced by {saved.Name}");
                    removed++;
                }
                else
                {
                    file.Update(FileState.Done, $"Saved as {saved.Name}; original kept: {whyKept}");
                    kept++;
                }
                WorkingFiles.DeletePickerCopy(file.Source, overwrite: true);
            }
            catch (OperationCanceledException)
            {
                file.Update(FileState.Pending, "Cancelled");
                cancelled = true;
            }
            catch (CryptographicException)
            {
                file.Update(FileState.Failed, "Wrong password, or the file is damaged");
                failed++;
            }
            catch (Exception ex)
            {
                file.Update(FileState.Failed, Describe(ex));
                failed++;
            }
            finally
            {
                WorkingFiles.TryDelete(tempPath);
                finished = before + Math.Max(0, file.Size);
            }
        }

        string past = mode == Mode.Encrypt ? "Encrypted" : "Decrypted";
        string message = $"{past} {savedCount} of {targets.Count} " + (targets.Count == 1 ? "file." : "files.");
        if (savedCount > 0)
        {
            message += chosen is null ? "\nSaved next to the originals." : $"\nSaved to: {chosen.DisplayName}";
        }
        if (removed > 0)
        {
            message += removed == 1 ? "\nThe original was deleted." : $"\n{removed} originals were deleted.";
        }
        if (kept > 0)
        {
            message += $"\n{kept} " + (kept == 1 ? "original was" : "originals were") + " kept: see the list above.";
        }
        if (failed > 0)
        {
            message += $"\n{failed} failed: see the list above.";
        }
        if (notSaved > 0)
        {
            message += $"\n{notSaved} not saved.";
        }
        if (cancelled)
        {
            message += "\nCancelled before the rest were done.";
        }

        bool allSaved = savedCount == targets.Count;
        ShowStatus(failed > 0 ? StatusKind.Error : allSaved && kept == 0 ? StatusKind.Success : StatusKind.Info, message);
        if (allSaved)
        {
            ClearPasswords();
        }
    }

    /// <summary>Reads a saved encrypted file back and checks that it fully decrypts.</summary>
    private static async Task<bool> SavedCopyDecryptsAsync(SavedOutput saved, string password, CancellationToken ct)
    {
        try
        {
            await Task.Run(() =>
            {
                using Stream stream = saved.OpenRead();
                PocketCrypto.Decrypt(stream, Stream.Null, password, cancellationToken: ct);
            }, ct);
            return true;
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidDataException or IOException
            or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Encrypts or decrypts into a new private temp file and returns its path.</summary>
    private static async Task<string> ProcessToTempAsync(SelectedFile file, Mode mode, string password,
        Action<long> onProgress, CancellationToken ct)
    {
        string tempPath = WorkingFiles.NewTempPath();
        try
        {
            await using Stream input = await file.Source.OpenReadAsync();
            var progress = new ThrottledProgress(onProgress);
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
            return tempPath;
        }
        catch
        {
            WorkingFiles.TryDelete(tempPath);
            throw;
        }
    }

    private static string OutputName(string fileName, Mode mode) =>
        mode == Mode.Encrypt ? OutputFiles.ForEncrypted(fileName) : OutputFiles.ForDecrypted(fileName);

    // ------------------------------------------------------------------
    // UI state helpers
    // ------------------------------------------------------------------

    private void SetProgress(long done, long total) =>
        WorkProgress.Progress = total > 0 ? Math.Min(1.0, done / (double)total) : 0;

    private void SetBusy(bool busy, string? message = null)
    {
        _busy = busy;
        BusyPanel.IsVisible = busy;
        BusySpinner.IsRunning = busy;
        BusyLabel.Text = message;
        if (busy)
        {
            WorkProgress.Progress = 0;
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
