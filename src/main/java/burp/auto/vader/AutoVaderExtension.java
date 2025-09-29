package burp.auto.vader;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.auto.vader.ui.AutoVaderContextMenu;
import java.nio.file.Paths;

public class AutoVaderExtension implements BurpExtension
{
    public static String chromiumPath;
    public static MontoyaApi api;
    public static String extensionName = "Auto Vader";
    public static String domInvaderPath = Paths.get(
        System.getProperty("user.home"),
        ".BurpSuite",
        "burp-chromium-extension",
        "dom-invader-extension"
        ).toString();
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(extensionName);
        api.logging().logToOutput(extensionName + " v1.0.0");
        AutoVaderExtension.api = api;
        api.userInterface().registerContextMenuItemsProvider(new AutoVaderContextMenu());
        chromiumPath = PlaywrightRenderer.getBurpChromiumPath();

    }
}