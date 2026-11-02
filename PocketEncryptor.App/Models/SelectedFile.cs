using System.ComponentModel;
using System.Runtime.CompilerServices;
using PocketEncryptor.App.Services;
using PocketEncryptor.Core;

namespace PocketEncryptor.App.Models;

public enum FileState { Pending, Working, Done, Failed, Skipped }

/// <summary>A file the user picked, and what happened to it.</summary>
public sealed class SelectedFile : INotifyPropertyChanged
{
    private FileState _state;
    private string _statusText = string.Empty;
    private double _progress;

    private SelectedFile(PickedFile picked, long size, bool isEncrypted)
    {
        Source = picked.File;
        Original = picked.Original;
        Size = size;
        IsEncrypted = isEncrypted;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>The file to read (on mobile, a private copy of the original).</summary>
    public FileResult Source { get; }

    /// <summary>The user's original, if the app is allowed to delete it.</summary>
    internal IOriginalFile? Original { get; }

    public string Name => Source.FileName;

    /// <summary>Size in bytes, or -1 if the platform can't tell.</summary>
    public long Size { get; }

    /// <summary>Starts with the PocketEncryptor header.</summary>
    public bool IsEncrypted { get; }

    public FileState State
    {
        get => _state;
        private set => Set(ref _state, value);
    }

    public string StatusText
    {
        get => _statusText;
        private set => Set(ref _statusText, value);
    }

    /// <summary>0 to 1 while <see cref="FileState.Working"/>.</summary>
    public double Progress
    {
        get => _progress;
        set => Set(ref _progress, value);
    }

    public void Update(FileState state, string statusText)
    {
        State = state;
        StatusText = statusText;
        if (state != FileState.Working)
        {
            Progress = 0;
        }
    }

    internal static async Task<SelectedFile> LoadAsync(PickedFile picked)
    {
        await using Stream stream = await picked.File.OpenReadAsync();
        long size;
        try
        {
            size = stream.CanSeek ? stream.Length : -1;
        }
        catch (NotSupportedException)
        {
            size = -1;
        }

        byte[] start = new byte[PkecFormat.Magic.Length];
        int read = await stream.ReadAtLeastAsync(start, start.Length, throwOnEndOfStream: false);
        return new SelectedFile(picked, size, PkecFormat.HasMagic(start.AsSpan(0, read)));
    }

    public static string FormatSize(long bytes) => bytes switch
    {
        < 0 => "size unknown",
        < 1024 => $"{bytes} bytes",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.#} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):0.##} GB",
    };

    private void Set<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
