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
		// Width/Height only apply on desktop (Windows, macOS).
#if MACCATALYST
		// A fixed, phone-sized window: the page is a single narrow column, and
		// macOS otherwise opens it at 1024×768. (Mac Catalyst draws these at 77%,
		// about 354×647 points on screen.)
		const double width = 460, height = 840;
		return new Window(new AppShell())
		{
			Title = "PocketEncryptor",
			Width = width,
			Height = height,
			MinimumWidth = width,
			MaximumWidth = width,
			MinimumHeight = height,
			MaximumHeight = height,
		};
#else
		// Wide enough for the desktop layout (sidebar, file list, password panel; see
		// MainPage.WideLayoutMinWidth). Narrowed below that, the page becomes a single column.
		return new Window(new AppShell())
		{
			Title = "PocketEncryptor",
			Width = 1120,
			Height = 760,
			MinimumWidth = 360,
			MinimumHeight = 560,
		};
#endif
	}
}
