using System.Runtime.InteropServices;

namespace PocketEncryptor.App.WinUI;

/// <summary>
/// The classic Windows Open and Select Folder dialogs (IFileOpenDialog), shown
/// in-process and modal to the app window.
/// </summary>
/// <remarks>
/// MAUI's FilePicker uses the WinRT FileOpenPicker, which runs through a broker
/// process. In this unpackaged app its PickMultipleFilesAsync fails with E_FAIL
/// whenever the user picks after browsing to a folder or selects more than one
/// file. The shell dialog has no broker and is the same dialog users know.
/// </remarks>
internal static class WindowsShellDialogs
{
    private const uint FosPickFolders = 0x20;
    private const uint FosForceFileSystem = 0x40;
    private const uint FosAllowMultiSelect = 0x200;
    private const uint FosPathMustExist = 0x800;
    private const uint FosFileMustExist = 0x1000;
    private const uint SigdnFileSysPath = 0x80058000;
    private const int HResultCancelled = unchecked((int)0x800704C7); // HRESULT_FROM_WIN32(ERROR_CANCELLED)

    /// <returns>The chosen files' full paths; empty if the user cancelled.</returns>
    public static IReadOnlyList<string> PickFiles(string title) =>
        Show(title, FosAllowMultiSelect | FosFileMustExist);

    /// <returns>The chosen folder's full path, or null if the user cancelled.</returns>
    public static string? PickFolder(string title) =>
        Show(title, FosPickFolders).FirstOrDefault();

    private static List<string> Show(string title, uint options)
    {
        var dialog = (IFileOpenDialog)new FileOpenDialogCoClass();
        try
        {
            dialog.GetOptions(out uint defaults);
            dialog.SetOptions(defaults | options | FosForceFileSystem | FosPathMustExist);
            dialog.SetTitle(title);

            int hr = dialog.Show(WindowsFileSaver.GetWindowHandle());
            if (hr == HResultCancelled)
            {
                return [];
            }
            Marshal.ThrowExceptionForHR(hr);

            dialog.GetResults(out IShellItemArray results);
            results.GetCount(out uint count);
            var paths = new List<string>((int)count);
            for (uint i = 0; i < count; i++)
            {
                results.GetItemAt(i, out IShellItem item);
                item.GetDisplayName(SigdnFileSysPath, out string path);
                paths.Add(path);
            }
            return paths;
        }
        finally
        {
            Marshal.ReleaseComObject(dialog);
        }
    }

    // ------------------------------------------------------------------
    // COM declarations (shobjidl_core.h)
    // ------------------------------------------------------------------

    [ComImport, Guid("DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7")]
    private class FileOpenDialogCoClass;

    [ComImport, Guid("D57C7288-D4AD-4768-BE02-9D969532D960"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IFileOpenDialog
    {
        // IModalWindow
        [PreserveSig] int Show(IntPtr parent);

        // IFileDialog
        void SetFileTypes(uint count, IntPtr filterSpec);
        void SetFileTypeIndex(uint index);
        void GetFileTypeIndex(out uint index);
        void Advise(IntPtr events, out uint cookie);
        void Unadvise(uint cookie);
        void SetOptions(uint options);
        void GetOptions(out uint options);
        void SetDefaultFolder(IShellItem item);
        void SetFolder(IShellItem item);
        void GetFolder(out IShellItem item);
        void GetCurrentSelection(out IShellItem item);
        void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string name);
        void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string name);
        void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string title);
        void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string text);
        void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string label);
        void GetResult(out IShellItem item);
        void AddPlace(IShellItem item, int placement);
        void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string extension);
        void Close(int hr);
        void SetClientGuid(ref Guid guid);
        void ClearClientData();
        void SetFilter(IntPtr filter);

        // IFileOpenDialog
        void GetResults(out IShellItemArray items);
        void GetSelectedItems(out IShellItemArray items);
    }

    [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItem
    {
        void BindToHandler(IntPtr bindContext, ref Guid handler, ref Guid riid, out IntPtr result);
        void GetParent(out IShellItem parent);
        void GetDisplayName(uint form, [MarshalAs(UnmanagedType.LPWStr)] out string name);
        void GetAttributes(uint mask, out uint attributes);
        void Compare(IShellItem other, uint hint, out int order);
    }

    [ComImport, Guid("B63EA76D-1F85-456F-A19C-48159EFA858B"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItemArray
    {
        void BindToHandler(IntPtr bindContext, ref Guid handler, ref Guid riid, out IntPtr result);
        void GetPropertyStore(int flags, ref Guid riid, out IntPtr result);
        void GetPropertyDescriptionList(IntPtr keyType, ref Guid riid, out IntPtr result);
        void GetAttributes(int attribFlags, uint mask, out uint attributes);
        void GetCount(out uint count);
        void GetItemAt(uint index, out IShellItem item);
        void EnumItems(out IntPtr enumerator);
    }
}
