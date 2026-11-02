using PocketEncryptor.App.Services;

namespace PocketEncryptor.App;

public partial class App : Application
{
	public App()
	{
		InitializeComponent();

		// Remove temp files left over if the app was killed mid-operation.
		WorkingFiles.CleanUpLeftovers();

#if WINDOWS
		// "Open with", double-clicking an associated .pkec file and "Send to"
		// start the app with the files as arguments.
		List<PickedFile> files = [.. Environment.GetCommandLineArgs().Skip(1)
			.Where(File.Exists)
			.Select(path => PickedFile.FromPath(Path.GetFullPath(path)))];
		IncomingFiles.Deliver(files);
#endif
	}

	protected override Window CreateWindow(IActivationState? activationState)
	{
		// Width/Height only apply on desktop (Windows, macOS). Wide enough for the
		// desktop layout (sidebar, file list, password panel; see MainPage.WideLayoutMinWidth);
		// narrowed below that, the page becomes a single column. (Mac Catalyst draws
		// these sizes at 77%, so about 862×585 points on screen.)
		return new Window(new AppShell())
		{
			Title = "PocketEncryptor",
			Width = 1120,
			Height = 760,
			MinimumWidth = 360,
			MinimumHeight = 560,
		};
	}
}
