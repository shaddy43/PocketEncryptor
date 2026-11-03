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

    /// <summary>From this page width on, the desktop layout: sidebar, files, password panel.</summary>
    public const double WideLayoutMinWidth = 900;
    private const string WrongPasswordMessage = "Wrong password, or the file is damaged or has been tampered with.";

    private readonly ObservableCollection<SelectedFile> _files = [];
    private Mode _mode = Mode.Encrypt;
    private CancellationTokenSource? _cts;
    private bool _busy;
    private bool? _wide;

    public MainPage()
    {
        InitializeComponent();
#if ANDROID
        // Status bar icons must flip with the theme: dark on the light page, light on the Vault black.
        // Re-applied on every theme change: the behavior only pushes values to Android when they're set.
        var statusBar = new CommunityToolkit.Maui.Behaviors.StatusBarBehavior();
        void ApplyStatusBar()
        {
            bool dark = Application.Current?.RequestedTheme == AppTheme.Dark;
            statusBar.StatusBarColor = Res(dark ? "OffBlack" : "PageLight");
            statusBar.StatusBarStyle = dark
                ? CommunityToolkit.Maui.Core.StatusBarStyle.LightContent
                : CommunityToolkit.Maui.Core.StatusBarStyle.DarkContent;
        }
        ApplyStatusBar();
        Behaviors.Add(statusBar);
        if (Application.Current is { } app)
        {
            app.RequestedThemeChanged += (_, _) => ApplyStatusBar();
        }
#endif
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
#if WINDOWS || IOS || MACCATALYST
        _normalStroke = FilesBorder.Stroke;
        _normalDropStroke = DropZone.Stroke;
        AddDropTarget(PageScroll);
        AddDropTarget(MainScroll);
#endif
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        ProcessIncoming(); // files shared or opened before the page existed
    }

    // ------------------------------------------------------------------
    // Layout: one column, or sidebar + files + password panel
    // ------------------------------------------------------------------

    protected override void OnSizeAllocated(double width, double height)
    {
        base.OnSizeAllocated(width, height);
        if (width > 0)
        {
            ApplyLayout(width >= WideLayoutMinWidth);
        }
    }

    /// <summary>Moves the sections between the narrow column and the wide panes.</summary>
    private void ApplyLayout(bool wide)
    {
        if (_wide == wide)
        {
            return;
        }
        _wide = wide;

        View[] moving = [FilesBorder, PasswordSection, ReplacePanel, RunButton, BusyPanel, ResultPanel, StatusBorder];
        foreach (View view in moving)
        {
            (view.Parent as Layout)?.Remove(view);
        }

        if (wide)
        {
            int at = MainStack.IndexOf(DropZone);
            MainStack.Insert(at++, FilesBorder);
            MainStack.Insert(at++, ResultPanel);
            MainStack.Insert(at, StatusBorder);
            foreach (View view in new View[] { PasswordSection, ReplacePanel, RunButton, BusyPanel })
            {
                PanelStack.Add(view);
            }
        }
        else
        {
            // Back into the column, in reading order, before the footer.
            int at = NarrowStack.IndexOf(ModeGrid) + 1;
            foreach (View view in moving)
            {
                NarrowStack.Insert(at++, view);
            }
        }

        PageScroll.IsVisible = !wide;
        WideGrid.IsVisible = wide;
#if WINDOWS || IOS || MACCATALYST
        DropZone.IsVisible = wide;
#endif
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
        StyleSidebarItem(SideEncryptButton, selected: encrypt);
        StyleSidebarItem(SideDecryptButton, selected: !encrypt);
        WideTitle.Text = encrypt ? "Encrypt" : "Decrypt";
        ConfirmEntry.IsVisible = encrypt;
        PasswordEntry.ReturnType = encrypt ? ReturnType.Next : ReturnType.Done;
        ReplacePanel.IsVisible = encrypt;
        if (!encrypt)
        {
            ReplaceCheckBox.IsChecked = false;
        }
        RefreshFileStatuses();
        UpdateState();
    }

    // ------------------------------------------------------------------
    // Purge: delete originals after encrypting
    // ------------------------------------------------------------------

    private bool RemoveOriginals => _mode == Mode.Encrypt && ReplaceCheckBox.IsChecked;

    private void OnReplaceLabelTapped(object? sender, TappedEventArgs e) =>
        ReplaceCheckBox.IsChecked = !ReplaceCheckBox.IsChecked;

    private void OnReplaceChanged(object? sender, CheckedChangedEventArgs e) => UpdateState();

    /// <summary>Asks before a run that deletes originals. False: don't run.</summary>
    private async Task<bool> ConfirmRemovingOriginalsAsync(List<SelectedFile> targets)
    {
        int removable = targets.Count(f => f.Original is { WhyNotRemovable: null });
        if (removable == 0)
        {
            ShowStatus(StatusKind.Info, (targets.Count == 1 ? "The app can't delete this original" : "The app can't delete these originals")
                + " (shared from another app, read-only, or stored where deleting isn't allowed). "
                + "Untick \"Purge\" to just encrypt.");
            return false;
        }

        string which = removable == targets.Count
            ? removable switch { 1 => "the original", 2 => "both originals", _ => $"all {removable} originals" }
            : $"{removable} of the {targets.Count} originals (the rest can't be deleted here and will be kept)";
        string message =
            $"Once each encrypted copy is saved and checked, {which} will be overwritten and deleted. "
            + "Without the password, they can't be recovered.";
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

    /// <summary>A mode item in the wide layout's dark sidebar.</summary>
    private static void StyleSidebarItem(Button button, bool selected)
    {
        if (selected)
        {
            button.SetAppThemeColor(BackgroundColorProperty, Res("Primary"), Res("PrimaryDark"));
            button.SetAppThemeColor(Button.TextColorProperty, Colors.White, Res("PrimaryDarkText"));
        }
        else
        {
            // Via SetAppThemeColor too: a plain value wouldn't replace the theme binding set when selected.
            button.SetAppThemeColor(BackgroundColorProperty, Colors.Transparent, Colors.Transparent);
            button.SetAppThemeColor(Button.TextColorProperty, Res("SidebarTextLight"), Res("MutedDark"));
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
            // With files already chosen, the button is "Add files" and picks more.
            await LoadFilesAsync(picked, append: _files.Count > 0);
        }
    }

    private void OnRemoveFileClicked(object? sender, EventArgs e)
    {
        if (_busy || (sender as BindableObject)?.BindingContext is not SelectedFile file)
        {
            return;
        }
        WorkingFiles.Release(file.Source, file.Original);
        _files.Remove(file);
        HideStatus();
        if (_files.Count > 0 && _files.All(f => f.State != FileState.Done))
        {
            SetMode(_files.All(f => f.IsEncrypted) ? Mode.Decrypt : Mode.Encrypt);
        }
        RefreshFileStatuses();
        ShowFiles();
        UpdateState();
    }

    /// <summary>
    /// Replaces the selection with these files (picked, shared, opened or dropped),
    /// or with <paramref name="append"/> adds them to it, leaving out files already chosen.
    /// </summary>
    private async Task LoadFilesAsync(IReadOnlyList<PickedFile> files, bool append = false)
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
                WorkingFiles.Release(file.File, file.Original);
            }
            ShowStatus(StatusKind.Error, "Couldn't open that file: " + Describe(ex));
            return;
        }

        if (append)
        {
            foreach (SelectedFile file in loaded.ToList())
            {
                SelectedFile? same = _files.FirstOrDefault(f => f.Source.FullPath == file.Source.FullPath)
                    ?? _files.FirstOrDefault(f => f.Name == file.Name && f.Size == file.Size);
                if (same is null)
                {
                    continue;
                }
                // Already chosen. A picker copy at a new path can go; the same path is still in use.
                if (same.Source.FullPath == file.Source.FullPath)
                {
                    (file.Original as IDisposable)?.Dispose();
                }
                else
                {
                    WorkingFiles.Release(file.Source, file.Original);
                }
                loaded.Remove(file);
            }
        }
        else
        {
            ClearFiles(keep: files);
        }

        foreach (SelectedFile file in loaded)
        {
            _files.Add(file);
        }
        HideStatus();

        // Pick the obvious mode: encrypted files get decrypted, anything else encrypted.
        IEnumerable<SelectedFile> considered = append ? _files.Where(f => f.State != FileState.Done) : loaded;
        if (considered.Any())
        {
            SetMode(considered.All(f => f.IsEncrypted) ? Mode.Decrypt : Mode.Encrypt);
        }
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

#if WINDOWS || IOS || MACCATALYST
    private Brush? _normalStroke;
    private Brush? _normalDropStroke;

    private void ShowDropHighlight(bool on)
    {
        FilesBorder.Stroke = on ? new SolidColorBrush(Res("Primary")) : _normalStroke;
        DropZone.Stroke = on ? new SolidColorBrush(Res("Primary")) : _normalDropStroke;
    }

    /// <summary>Accepts files dragged onto the window, e.g. from File Explorer or Finder.</summary>
    private void AddDropTarget(View target)
    {
        var drop = new DropGestureRecognizer { AllowDrop = true };
        drop.DragOver += (_, e) =>
        {
            if (_busy)
            {
                return;
            }
            e.AcceptedOperation = DataPackageOperation.Copy;
#if WINDOWS
            if (e.PlatformArgs?.DragEventArgs is { } args)
            {
                args.AcceptedOperation = global::Windows.ApplicationModel.DataTransfer.DataPackageOperation.Copy;
                args.DragUIOverride.Caption = "Add to PocketEncryptor";
            }
#endif
            ShowDropHighlight(true);
        };
        drop.DragLeave += (_, _) => ShowDropHighlight(false);
        drop.Drop += OnDrop;
        target.GestureRecognizers.Add(drop);
    }

    private async void OnDrop(object? sender, DropEventArgs e)
    {
        ShowDropHighlight(false);
#if WINDOWS
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
        int failed = 0;
#else
        if (_busy || e.PlatformArgs?.DropSession is not { } session)
        {
            return;
        }
        e.Handled = true;

        (List<PickedFile> files, bool hadFolders, int failed) = await AppleIncomingFiles.ReadDropAsync(session);
#endif

        if (files.Count > 0)
        {
            await LoadFilesAsync(files, append: _files.Count > 0); // dropping adds, like "Add files"
        }
        if (hadFolders)
        {
            ShowStatus(StatusKind.Info, files.Count > 0
                ? "Folders were left out: only files can be added."
                : "Folders can't be added yet. Drop the files inside them instead.");
        }
        else if (failed > 0)
        {
            ShowStatus(StatusKind.Error, files.Count > 0
                ? $"{failed} of the dropped files couldn't be read and were left out."
                : "Couldn't read the dropped files.");
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
            (file.Original as IDisposable)?.Dispose(); // a kept file comes with its own access
        }
        _files.Clear();
        ShowFiles();
        UpdateState();
    }

    private void ShowFiles()
    {
        int count = _files.Count;
        FileList.IsVisible = count > 0;
        PickFileButton.Text = count > 0 ? "Add files" : "Choose files";
        SemanticProperties.SetHint(PickFileButton, count > 0 ? "Adds more files to the list" : null);

        if (count == 0)
        {
            FileNameLabel.Text = "No files chosen";
            FileInfoLabel.Text = "Pick files to encrypt, or .pkec files to decrypt.";
            WideSubtitle.Text = "Choose or drop files to start.";
            return;
        }

        int encrypted = _files.Count(f => f.IsEncrypted);
        int done = _files.Count(f => f.State == FileState.Done);
        string size = SelectedFile.FormatSize(_files.Sum(f => Math.Max(0, f.Size)));
        FileNameLabel.Text = count == 1 ? "1 file" : $"{count} files";
        FileInfoLabel.Text =
            done == count ? $"{size} · all done"
            : done > 0 ? $"{size} · {done} of {count} done"
            : encrypted == 0 ? $"{size} · will be encrypted"
            : encrypted == count ? $"{size} · encrypted: enter the password to decrypt"
            : $"{encrypted} encrypted, {count - encrypted} not. Each mode skips the files it doesn't apply to.";
        WideSubtitle.Text = $"{FileNameLabel.Text} · {size}";
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

    private void OnShowPasswordClicked(object? sender, EventArgs e) => SetPasswordsVisible(PasswordEntry.IsPassword);

    private void SetPasswordsVisible(bool visible)
    {
        PasswordEntry.IsPassword = !visible;
        ConfirmEntry.IsPassword = !visible;
        ShowPasswordButton.Text = visible ? "Hide" : "Show";
        SemanticProperties.SetDescription(ShowPasswordButton, visible ? "Hide password" : "Show password");
    }

    private void ClearPasswords()
    {
        PasswordEntry.Text = string.Empty;
        ConfirmEntry.Text = string.Empty;
        SetPasswordsVisible(false);
    }

    /// <summary>
    /// A rough guide (0-4) from length and character variety. Says nothing about
    /// dictionary words, so it's shown as a hint, never as a guarantee.
    /// </summary>
    private static int PasswordStrength(string password)
    {
        if (password.Length == 0)
        {
            return 0;
        }
        int kinds = (password.Any(char.IsLower) ? 1 : 0) + (password.Any(char.IsUpper) ? 1 : 0)
            + (password.Any(char.IsDigit) ? 1 : 0) + (password.Any(c => !char.IsLetterOrDigit(c)) ? 1 : 0);
        return password.Length switch
        {
            < RecommendedPasswordLength => 1,
            < 12 => kinds >= 3 ? 3 : 2,
            < 16 => kinds >= 2 ? 3 : 2,
            _ => kinds >= 2 ? 4 : 3,
        };
    }

    private void ShowStrength(string password)
    {
        int score = PasswordStrength(password);
        StrengthPanel.IsVisible = _mode == Mode.Encrypt && score > 0;
        if (!StrengthPanel.IsVisible)
        {
            return;
        }
        (string text, string light, string dark) = score switch
        {
            1 => ("Weak", "ErrorLight", "ErrorDark"),
            2 => ("Fair", "MutedLight", "MutedDark"),
            3 => ("Strong", "Primary", "PrimaryDark"),
            _ => ("Very strong", "Primary", "PrimaryDark"),
        };
        BoxView[] bars = [Strength1, Strength2, Strength3, Strength4];
        for (int i = 0; i < bars.Length; i++)
        {
            if (i < score)
            {
                bars[i].SetAppThemeColor(BoxView.ColorProperty, Res(light), Res(dark));
            }
            else
            {
                bars[i].SetAppThemeColor(BoxView.ColorProperty, Res("BorderLight"), Res("BorderDark"));
            }
        }
        StrengthLabel.Text = text;
        StrengthLabel.SetAppThemeColor(Label.TextColorProperty, Res(light), Res(dark));
        SemanticProperties.SetDescription(StrengthPanel, "Password strength: " + text);
    }

    // Enables the Run button only when the input is complete, and explains why not.
    private void UpdateState()
    {
        string password = PasswordEntry.Text ?? string.Empty;
        string confirm = ConfirmEntry.Text ?? string.Empty;

        string? hint = null;
        (string light, string dark) hintColor = ("MutedLight", "MutedDark");
        bool passwordOk = password.Length > 0;

        ShowStrength(password);
        if (_mode == Mode.Encrypt && password.Length > 0)
        {
            if (confirm.Length > 0 && confirm != password)
            {
                hint = "Passwords don't match.";
                hintColor = ("ErrorLight", "ErrorDark");
            }
            else if (password.Length < RecommendedPasswordLength)
            {
                hint = $"Tip: use at least {RecommendedPasswordLength} characters. Longer passwords are much harder to guess.";
            }
            else if (confirm == password)
            {
                hint = "✓ Passwords match.";
                hintColor = ("Primary", "PrimaryDark");
            }
            passwordOk = confirm == password;
        }

        PasswordHintLabel.IsVisible = hint is not null;
        PasswordHintLabel.Text = hint;
        PasswordHintLabel.SetAppThemeColor(Label.TextColorProperty, Res(hintColor.light), Res(hintColor.dark));

        int runnable = RunnableFiles().Count;
        string verb = _mode == Mode.Encrypt ? "Encrypt" : "Decrypt";
        if (runnable == 0 && _files.Count > 0)
        {
            // Every file is done, or none of them applies to this mode.
            string left = _files.Any(f => f.State == FileState.Done) ? "left " : "";
            RunButton.Text = $"Nothing {left}to {verb.ToLowerInvariant()}";
            RunButton.ClearValue(BackgroundColorProperty);
        }
        else if (RemoveOriginals)
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
        SideEncryptButton.IsEnabled = !_busy;
        SideDecryptButton.IsEnabled = !_busy;
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
            ShowFiles(); // the card's summary now counts the files done
        }
        ProcessIncoming(); // anything shared while busy
    }

    /// <summary>One file: process it, then a Save dialog with the suggested name.</summary>
    private async Task RunSingleAsync(SelectedFile file, Mode mode, string password, CancellationToken ct)
    {
        string? tempPath = null;
        file.Update(FileState.Working, mode == Mode.Encrypt ? "Encrypting…" : "Decrypting…");
        try
        {
            // 1. Produce the full result in private temp storage. For decryption
            //    this means the whole file has authenticated before we save it.
            tempPath = await ProcessToTempAsync(file, mode, password, done =>
            {
                SetProgress(done, file.Size);
                file.Progress = WorkProgress.Progress;
            }, ct);

            // 2. Let the user choose where it goes (native Save dialog).
            BusyLabel.Text = "Choose where to save…";
            string? savedPath = await OutputSaver.SaveAsync(tempPath, OutputName(file.Name, mode), file.Source.FullPath, ct);
            if (savedPath is null)
            {
                ShowStatus(StatusKind.Info, "Not saved. Press the button again when you're ready to save.");
                return;
            }

            string verb = mode == Mode.Encrypt ? "Encrypted" : "Decrypted";
            ClearPasswords();
            ClearFiles();
            ShowResult(StatusKind.Success, $"{verb} 1 file", $"{file.Name}\nSaved to: {savedPath}");
        }
        catch (SaveRefusedException ex)
        {
            ShowStatus(StatusKind.Error, ex.Message);
        }
        catch (CryptographicException)
        {
            file.Update(FileState.Failed, "Wrong password, or the file is damaged");
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
            if (file.State == FileState.Working)
            {
                RefreshFileStatuses(); // not saved, cancelled or an error: back to its size
            }
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
                tempPath = await ProcessToTempAsync(file, mode, password, done =>
                {
                    SetProgress(before + done, total);
                    file.Progress = file.Size > 0 ? Math.Min(1.0, done / (double)file.Size) : 0;
                }, ct);
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
        string title = savedCount == targets.Count
            ? $"{past} " + (savedCount == 1 ? "1 file" : $"{savedCount} files")
            : $"{savedCount} of {targets.Count} {past.ToLowerInvariant()}";
        string message = savedCount == 0 ? "Nothing was saved."
            : chosen is null ? "Saved next to the originals." : $"Saved to: {chosen.DisplayName}";
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

        if (failed > 0)
        {
            message += _mode == Mode.Decrypt
                ? "\nTo retry the failed ones, enter their password and press the button again."
                : "\nPress the button again to retry the failed ones.";
        }

        bool allSaved = savedCount == targets.Count;
        ShowResult(failed > 0 ? StatusKind.Error : allSaved && kept == 0 ? StatusKind.Success : StatusKind.Info, title, message);
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
            StatusKind.Success => ("Secondary", "Tertiary", "MidnightBlue", "DarkText"),
            StatusKind.Error => ("ErrorBackgroundLight", "ErrorBackgroundDark", "ErrorLight", "ErrorDark"),
            _ => ("Gray100", "SurfaceDark", "MidnightBlue", "DarkText"),
        };
        StatusBorder.SetAppThemeColor(BackgroundColorProperty, Res(bgLight), Res(bgDark));
        StatusLabel.SetAppThemeColor(Label.TextColorProperty, Res(fgLight), Res(fgDark));
        ResultPanel.IsVisible = false;
        StatusBorder.IsVisible = true;
        SemanticScreenReader.Announce(message);
    }

    /// <summary>The summary of a finished run, with a Done button that clears the list.</summary>
    private void ShowResult(StatusKind kind, string title, string details)
    {
        ResultTitle.Text = title;
        ResultDetail.Text = details;
        (string bgLight, string bgDark, string fgLight, string fgDark) = kind switch
        {
            StatusKind.Success => ("Secondary", "Tertiary", "MidnightBlue", "DarkText"),
            StatusKind.Error => ("ErrorBackgroundLight", "ErrorBackgroundDark", "ErrorLight", "ErrorDark"),
            _ => ("Gray100", "SurfaceDark", "MidnightBlue", "DarkText"),
        };
        ResultPanel.SetAppThemeColor(BackgroundColorProperty, Res(bgLight), Res(bgDark));
        ResultTitle.SetAppThemeColor(Label.TextColorProperty, Res(fgLight), Res(fgDark));
        ResultDetail.SetAppThemeColor(Label.TextColorProperty, Res(fgLight), Res(fgDark));
        StatusBorder.IsVisible = false;
        ResultPanel.IsVisible = true;
        SemanticScreenReader.Announce(title + ". " + details);
#if !WINDOWS && !MACCATALYST
        if (_wide != true)
        {
            _ = PageScroll.ScrollToAsync(ResultPanel, ScrollToPosition.MakeVisible, true);
        }
#endif
    }

    private void OnResultDoneClicked(object? sender, EventArgs e)
    {
        if (_busy)
        {
            return;
        }
        ClearFiles();
        ClearPasswords();
        HideStatus();
    }

    private void HideStatus()
    {
        StatusBorder.IsVisible = false;
        ResultPanel.IsVisible = false;
    }

    private static Color Res(string key) =>
        Application.Current?.Resources.TryGetValue(key, out object? value) == true && value is Color color
            ? color
            : Colors.Gray;
}
