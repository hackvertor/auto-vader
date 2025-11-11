package burp.auto.vader;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.api.montoya.ui.hotkey.HotKeyHandler;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;
import burp.auto.vader.actions.AutoVaderActions;
import burp.auto.vader.ui.AutoVaderContextMenu;
import burp.auto.vader.ui.AutoVaderMenuBar;

import javax.swing.*;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
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
    private AutoVaderActions actions;
    public static IssueDeduplicator deduper;
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(extensionName);
        api.logging().logToOutput(extensionName + " v1.0.6");
        AutoVaderExtension.api = api;
        String canary = api.persistence().extensionData().getString("canary");
        if(canary == null) {
            canary = Utils.generateCanary();
            api.persistence().extensionData().setString("canary", canary);
        }
        projectCanary = canary;
        sharedConfig = new DOMInvaderConfig();
        deduper = new IssueDeduplicator(api);
        actions = new AutoVaderActions(deduper);
        api.userInterface().registerContextMenuItemsProvider(new AutoVaderContextMenu(deduper));
        api.userInterface().menuBar().registerMenu(AutoVaderMenuBar.generateMenuBar());
        api.extension().registerUnloadingHandler(this);
        api.http().registerHttpHandler(new AutoVaderHandler());
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
                        Path to DOM Invader - If the autodetection fails you can specify a custom path
                        Path to Burp Chromium - If the autodetection fails you can specify a custom path to the executable
                        Payload - The payload to send along with the canary when scanning query parameters
                        HTML tags to scan - You can scan specific tags for gadgets. Used in conjunction with attributes
                        Attributes to scan - Scans specific attributes for gadgets.
                        Delay - The amount of delay between requests in ms
                        Always open devtools - Each time the browser window is open the devtools panel will be shown
                        Remove CSP - CSP can break the callbacks that DOM Invader uses to function
                        Headless - Run scans headlessly
                        Auto run from Repeater - This runs AutoVader when a Repeater request is sent
                        Auto run from Intruder - This runs AutoVader when a Intruder request is sent
                        """)
                .withKeywords("Auto", "Vader", "AutoVader", "AutoVader settings")
                .withSettings(
                        SettingsPanelSetting.stringSetting("Path to DOM Invader", domInvaderPath),
                        SettingsPanelSetting.stringSetting("Path to Burp Chromium", chromiumPath),
                        SettingsPanelSetting.stringSetting("Payload", ""),
                        SettingsPanelSetting.stringSetting("HTML tags to scan", "div,b,span"),
                        SettingsPanelSetting.stringSetting("Attributes to scan", "data-src,title"),
                        SettingsPanelSetting.integerSetting("Delay MS", 0),
                        SettingsPanelSetting.booleanSetting("Always open devtools", false),
                        SettingsPanelSetting.booleanSetting("Remove CSP", true),
                        SettingsPanelSetting.booleanSetting("Headless", false),
                        SettingsPanelSetting.booleanSetting("Auto run from Repeater", false),
                        SettingsPanelSetting.booleanSetting("Auto run from Intruder", false)
                )
                .build();
        api.userInterface().registerSettingsPanel(settings);
        Burp burp = new Burp(api.burpSuite().version());
        if(burp.hasCapability(Burp.Capability.REGISTER_HOTKEY)) {
            registerAllHotkeys(api, burp);
        }
    }

    public static void alert(String msg) {
        JOptionPane.showMessageDialog(null, msg);
    }

    private void registerAllHotkeys(MontoyaApi montoyaApi, Burp burp) {
        List<HotkeyDefinition> hotkeys = Arrays.asList(
                // Open DOM Invader
                new HotkeyDefinition("Open DOM Invader", "Ctrl+Alt+D", event -> {
                    String url = AutoVaderActions.extractUrlFromMessageEditor(event.messageEditorRequestResponse().orElse(null));
                    if (url != null) {
                        actions.openDOMInvader(url);
                    }
                }),

                // Scan all GET params
                new HotkeyDefinition("Scan all GET params", "Ctrl+Alt+G", event -> {
                    List<String> urls = AutoVaderActions.extractUrlsFromMessageEditor(event.messageEditorRequestResponse().orElse(null));
                    if (!urls.isEmpty()) {
                        actions.scanAllQueryParameters(urls);
                    }
                }),

                // Scan all POST params
                new HotkeyDefinition("Scan all POST params", "Ctrl+Alt+P", event -> {
                    List<HttpRequestResponse> requestResponses = AutoVaderActions.extractRequestResponsesFromMessageEditor(event.messageEditorRequestResponse().orElse(null));
                    if (!requestResponses.isEmpty()) {
                        actions.scanAllPostParameters(requestResponses);
                    }
                }),

                // Scan web messages
                new HotkeyDefinition("Scan web messages", "Ctrl+Alt+W", event -> {
                    List<String> urls = AutoVaderActions.extractUrlsFromMessageEditor(event.messageEditorRequestResponse().orElse(null));
                    if (!urls.isEmpty()) {
                        actions.scanWebMessages(urls);
                    }
                }),

                // Inject into all sources
                new HotkeyDefinition("Inject into all sources", "Ctrl+Alt+I", event -> {
                    List<String> urls = AutoVaderActions.extractUrlsFromMessageEditor(event.messageEditorRequestResponse().orElse(null));
                    if (!urls.isEmpty()) {
                        actions.injectIntoAllSources(urls);
                    }
                }),

                // Inject into all sources & click everything
                new HotkeyDefinition("Inject into all sources & click", "Ctrl+Alt+C", event -> {
                    List<String> urls = AutoVaderActions.extractUrlsFromMessageEditor(event.messageEditorRequestResponse().orElse(null));
                    if (!urls.isEmpty()) {
                        actions.injectIntoAllSourcesAndClick(urls);
                    }
                }),

                // Scan for client side prototype pollution
                new HotkeyDefinition("Scan prototype pollution", "Ctrl+Shift+S", event -> {
                    List<String> urls = AutoVaderActions.extractUrlsFromMessageEditor(event.messageEditorRequestResponse().orElse(null));
                    if (!urls.isEmpty()) {
                        actions.scanPrototypePollution(urls);
                    }
                }),

                // Scan for client side prototype pollution gadgets
                new HotkeyDefinition("Scan prototype pollution gadgets", "Ctrl+Shift+G", event -> {
                    List<String> urls = AutoVaderActions.extractUrlsFromMessageEditor(event.messageEditorRequestResponse().orElse(null));
                    if (!urls.isEmpty()) {
                        actions.scanPrototypePollutionGadgets(urls);
                    }
                }),

                // Intercept client side redirect
                new HotkeyDefinition("Intercept client side redirect", "Ctrl+Alt+R", event -> {
                    String url = AutoVaderActions.extractUrlFromMessageEditor(event.messageEditorRequestResponse().orElse(null));
                    if (url != null) {
                        actions.interceptClientSideRedirect(url);
                    }
                })
        );

        for (HotkeyDefinition hotkey : hotkeys) {
            registerHotkey(montoyaApi, burp, hotkey);
        }
    }

    private static class HotkeyDefinition {
        final String name;
        final String keyCombo;
        final HotKeyHandler handler;

        HotkeyDefinition(String name, String keyCombo, HotKeyHandler handler) {
            this.name = name;
            this.keyCombo = keyCombo;
            this.handler = handler;
        }
    }

    private void registerHotkey(MontoyaApi montoyaApi, Burp burp, HotkeyDefinition hotkey) {
        Registration registration;

        if(burp.hasCapability(Burp.Capability.REGISTER_HOTKEY_WITH_NAME)) {
            registration = montoyaApi.userInterface().registerHotKeyHandler(
                    HotKeyContext.HTTP_MESSAGE_EDITOR,
                    HotKey.hotKey(hotkey.name, hotkey.keyCombo),
                    hotkey.handler);
        } else {
            registration = montoyaApi.userInterface().registerHotKeyHandler(
                    HotKeyContext.HTTP_MESSAGE_EDITOR,
                    hotkey.keyCombo,
                    hotkey.handler);
        }

        if(registration.isRegistered()) {
            montoyaApi.logging().logToOutput("Successfully registered hotkey: " + hotkey.name + " (" + hotkey.keyCombo + ")");
        } else {
            montoyaApi.logging().logToError("Failed to register hotkey: " + hotkey.name + " (" + hotkey.keyCombo + ")");
        }
    }

    @Override
    public void extensionUnloaded() {
        executorService.shutdown();
        api.logging().logToOutput(extensionName + " unloaded");
    }
}