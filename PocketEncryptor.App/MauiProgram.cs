using CommunityToolkit.Maui;
using Microsoft.Extensions.Logging;
using Microsoft.Maui.LifecycleEvents;

namespace PocketEncryptor.App;

public static class MauiProgram
{
	public static MauiApp CreateMauiApp()
	{
		var builder = MauiApp.CreateBuilder();
		builder
			.UseMauiApp<App>()
			.UseMauiCommunityToolkit()
			.ConfigureFonts(fonts =>
			{
				fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
				fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
			})
			.ConfigureLifecycleEvents(events =>
			{
#if ANDROID
				// Delivers the system pickers' results (see AndroidActivityResults).
				events.AddAndroid(android => android.OnActivityResult(Droid.AndroidActivityResults.OnActivityResult));
#elif IOS || MACCATALYST
				// "Open with" in Finder, "Open in" or Share from Files and other apps:
				// at launch, or while running.
				events.AddiOS(ios => ios
					.SceneWillConnect((_, _, options) => Services.AppleIncomingFiles.Open(options.UrlContexts))
					.SceneOpenUrl((_, contexts) => Services.AppleIncomingFiles.Open(contexts)));
#endif
			});

#if DEBUG
		builder.Logging.AddDebug();
#endif

		return builder.Build();
	}
}
