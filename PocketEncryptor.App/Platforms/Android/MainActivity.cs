using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;

namespace PocketEncryptor.App;

// SingleTask: a share from another app comes to the one running instance
// (OnNewIntent) instead of starting a second copy inside the other app.
[Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true, LaunchMode = LaunchMode.SingleTask, ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
// "Share → PocketEncryptor" for one or several files of any type.
[IntentFilter([Intent.ActionSend], Categories = [Intent.CategoryDefault], DataMimeType = "*/*")]
[IntentFilter([Intent.ActionSendMultiple], Categories = [Intent.CategoryDefault], DataMimeType = "*/*")]
// "Open with → PocketEncryptor" for .pkec files, which Android reports as generic binary files.
[IntentFilter([Intent.ActionView], Categories = [Intent.CategoryDefault], DataMimeType = "application/octet-stream")]
public class MainActivity : MauiAppCompatActivity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        if (savedInstanceState is null)
        {
            Droid.AndroidShareReceiver.Handle(Intent);
        }
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        Droid.AndroidShareReceiver.Handle(intent);
    }
}
