using Foundation;
using UIKit;

namespace PocketEncryptor.App;

// Apps built with the iOS 27 SDK must use the UIScene life cycle; see
// UIApplicationSceneManifest in Info.plist.
[Register("SceneDelegate")]
public class SceneDelegate : MauiUISceneDelegate
{
	public override void WillConnect(UIScene scene, UISceneSession session, UISceneConnectionOptions connectionOptions)
	{
		base.WillConnect(scene, session, connectionOptions);

		// The window has a fixed, phone-like size (see App.CreateWindow), so no full screen.
		if (scene is UIWindowScene { SizeRestrictions: { } restrictions })
		{
			restrictions.AllowsFullScreen = false;
		}
	}
}
