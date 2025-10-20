package burp.auto.vader;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;
import burp.auto.vader.ui.AutoVaderContextMenu;
import burp.auto.vader.ui.AutoVaderMenuBar;

import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AutoVaderExtension implements BurpExtension, ExtensionUnloadingHandler
{
    public static MontoyaApi api;
    public static String extensionName = "AutoVader";
    public static SettingsPanelWithData settings;
    public static final ExecutorService executorService = Executors.newSingleThreadExecutor();
    public static String projectCanary = null;
    public static String domInvaderPath;
    public static String chromiumPath;
    public static DOMInvaderConfig sharedConfig;
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
        // Initialize shared config that will load persisted callbacks
        sharedConfig = new DOMInvaderConfig();
        api.userInterface().registerContextMenuItemsProvider(new AutoVaderContextMenu(new IssueDeduplicator(api)));
        api.userInterface().menuBar().registerMenu(AutoVaderMenuBar.generateMenuBar());
        AutoVaderExtension.domInvaderPath = Paths.get(
                System.getProperty("user.home"),
                ".BurpSuite",
                "burp-chromium-extension",
                "dom-invader-extension"
        ).toString();
        AutoVaderExtension.chromiumPath = PlaywrightRenderer.getBurpChromiumPath();
        settings = SettingsPanelBuilder.settingsPanel()
                .withPersistence(SettingsPanelPersistence.PROJECT_SETTINGS)
                .withTitle("AutoVader Settings")
                .withDescription("""
                        Path to Burp Chromium - If the autodetection fails you can specify a custom path
                        Payload - The payload to send along with the canary when scanning query parameters
                        Delay - The amount of delay between requests in ms
                        Always open devtools - Each time the browser window is open the devtools panel will be shown
                        Remove CSP - CSP can break the callbacks that DOM Invader uses to function
                        """)
                .withKeywords("DOM", "Invader", "Auto", "Vader", "AutoVader")
                .withSettings(
                        SettingsPanelSetting.stringSetting("Path to Burp Chromium", ""),
                        SettingsPanelSetting.stringSetting("Payload", ""),
                        SettingsPanelSetting.integerSetting("Delay MS", 0),
                        SettingsPanelSetting.booleanSetting("Always open devtools", false),
                        SettingsPanelSetting.booleanSetting("Remove CSP", true)
                )
                .build();
        api.userInterface().registerSettingsPanel(settings);
    }

    @Override
    public void extensionUnloaded() {
        executorService.shutdown();
    }
}