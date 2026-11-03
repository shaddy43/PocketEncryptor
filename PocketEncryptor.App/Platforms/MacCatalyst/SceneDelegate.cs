using CoreGraphics;
using Foundation;
using UIKit;

namespace PocketEncryptor.App;

// Apps built with the iOS 27 SDK must use the UIScene life cycle; see
// UIApplicationSceneManifest in Info.plist. The window is resizable (and can go
// full screen): wide, the page shows the desktop layout; narrow, a single column.
[Register("SceneDelegate")]
public class SceneDelegate : MauiUISceneDelegate
{
	private const string WindowSizedKey = "mac_window_sized";

	/// <summary>
	/// Mac Catalyst opens a new window at 1024×768 whatever MAUI's Window.Width/Height
	/// say, so this sizes it when the scene becomes active (see MauiProgram), on the
	/// first launch only: after that macOS restores the size the user left it at.
	/// </summary>
	internal static void SizeFirstWindow(UIScene scene)
	{
		if (scene is not UIWindowScene windowScene || Preferences.Default.Get(WindowSizedKey, false))
		{
			return;
		}
		Preferences.Default.Set(WindowSizedKey, true);

		// The app's sizes are in iPad points, which macOS draws at 77%; SystemFrame
		// is in Mac points. Keep the window centred where macOS put it.
		const double MacScale = 0.77;
		CGRect current = windowScene.EffectiveGeometry.SystemFrame;
		nfloat width = (nfloat)(App.WindowWidth * MacScale), height = (nfloat)(App.WindowHeight * MacScale);
		var frame = new CGRect(
			current.X + (current.Width - width) / 2,
			current.Y + (current.Height - height) / 2,
			width, height);
		windowScene.RequestGeometryUpdate(new UIWindowSceneGeometryPreferencesMac(frame), _ => { });
	}
}
