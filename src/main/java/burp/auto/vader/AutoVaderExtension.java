package burp.auto.vader;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;
import burp.auto.vader.ui.AutoVaderContextMenu;

import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AutoVaderExtension implements BurpExtension
{
    public static MontoyaApi api;
    public static String extensionName = "AutoVader";
    public static SettingsPanelWithData settings;
    public static final ExecutorService executorService = Executors.newSingleThreadExecutor();
    public static String projectCanary = null;
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(extensionName);
        api.logging().logToOutput(extensionName + " v1.0.0");
        AutoVaderExtension.api = api;
        String canary = api.persistence().extensionData().getString("canary");
        if(canary == null) {
            canary = Utils.generateCanary();
            api.persistence().extensionData().setString("canary", canary);
        }
        projectCanary = canary;
        api.userInterface().registerContextMenuItemsProvider(new AutoVaderContextMenu(new IssueDeduplicator(api)));
        String domInvaderPath = Paths.get(
                System.getProperty("user.home"),
                ".BurpSuite",
                "burp-chromium-extension",
                "dom-invader-extension"
        ).toString();
        String chromiumPath = PlaywrightRenderer.getBurpChromiumPath();
        settings = SettingsPanelBuilder.settingsPanel()
                .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
                .withTitle("AutoVader Settings")
                .withDescription("""                       
                        Burp Chromium path - Is the path to where Burp browser is installed
                        DOM Invader path - The path where the DOM Invader extension is installed 
                        Payload - The payload to send along with the canary when scanning query parameters
                        Remove security headers - Removes CSP and X-Frame-Options required in order for DOM Invader to function                     
                        """)
                .withKeywords("DOM", "Invader", "Auto", "Vader", "AutoVader")
                .withSettings(
                        SettingsPanelSetting.stringSetting("Burp Chromium path", chromiumPath),
                        SettingsPanelSetting.stringSetting("DOM Invader path", domInvaderPath),
                        SettingsPanelSetting.stringSetting("Payload", ""),
                        SettingsPanelSetting.booleanSetting("Remove security headers", true)
                )
                .build();
        api.userInterface().registerSettingsPanel(settings);
    }
}