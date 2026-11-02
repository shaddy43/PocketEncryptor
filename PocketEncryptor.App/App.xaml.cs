using PocketEncryptor.App.Services;

namespace PocketEncryptor.App;

public partial class App : Application
{
	public App()
	{
		InitializeComponent();

		// Remove temp files left over if the app was killed mid-operation.
		WorkingFiles.CleanUpLeftovers();
	}

	protected override Window CreateWindow(IActivationState? activationState)
	{
		// Width/Height only apply on desktop (Windows, macOS).
		return new Window(new AppShell())
		{
			Title = "PocketEncryptor",
			Width = 520,
			Height = 820,
			MinimumWidth = 360,
			MinimumHeight = 560,
		};
	}
}
