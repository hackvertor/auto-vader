package burp.auto.vader;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.WaitUntilState;

import java.io.File;
import java.nio.file.Paths;
import java.util.List;

import static burp.auto.vader.AutoVaderExtension.*;

/**
 * Playwright-based browser renderer with DOM Invader extension support.
 *
 * Example usage with different profiles:
 * <pre>
 * // Default profile
 * PlaywrightRenderer renderer = new PlaywrightRenderer();
 *
 * // Custom canary
 * PlaywrightRenderer renderer = new PlaywrightRenderer(
 *     new DOMInvaderConfig(DOMInvaderConfig.customProfile("mycustom123"))
 * );
 *
 * // Full custom profile
 * DOMInvaderConfig.Profile profile = new DOMInvaderConfig.Profile()
 *     .setCanary("testcanary")
 *     .setPrototypePollution(true)
 *     .setDomClobbering(true)
 *     .setPostmessage(true)
 *     .setInjectCanary(true);
 * PlaywrightRenderer renderer = new PlaywrightRenderer(new DOMInvaderConfig(profile));
 * </pre>
 */
public class PlaywrightRenderer {

    private final DOMInvaderConfig domInvaderConfig;

    public PlaywrightRenderer() {
        this(new DOMInvaderConfig());
    }

    public PlaywrightRenderer(DOMInvaderConfig domInvaderConfig) {
        this.domInvaderConfig = domInvaderConfig;
    }

    public void renderUrls(List<String> urls, String extensionPath, boolean closeBrowser, boolean headless) {
        Playwright playwright = null;
        BrowserContext ctx = null;
        try {
            String homeDir = System.getProperty("user.home");
            File autoVaderDir = new File(homeDir, ".AutoVader");
            if (!autoVaderDir.exists()) {
                autoVaderDir.mkdirs();
                api.logging().logToOutput("Created AutoVader directory at: " + autoVaderDir.getAbsolutePath());
            }

            playwright = Playwright.create();
            BrowserType.LaunchPersistentContextOptions launchOptions = new BrowserType.LaunchPersistentContextOptions();
            String chromiumPath = settings.getString("Burp Chromium path");
            if (!chromiumPath.isEmpty()) {
                launchOptions.setExecutablePath(Paths.get(chromiumPath));
                api.logging().logToOutput("Using Burp Chromium at: " + chromiumPath);
            } else {
                api.logging().logToOutput("Burp Chromium not found, using system browser");
            }

            String userDataDir = new File(autoVaderDir, "browser-profile").getAbsolutePath();

            if (extensionPath != null && !extensionPath.isEmpty()) {
                launchOptions.setArgs(java.util.Arrays.asList(
                        "--disable-extensions-except=" + extensionPath,
                        "--load-extension=" + extensionPath
                )).setHeadless(headless);
            } else {
                launchOptions.setHeadless(headless);
            }

            ctx = playwright.chromium().launchPersistentContext(Paths.get(userDataDir), launchOptions);
            String extId = null;

            if (extensionPath != null && !extensionPath.isEmpty()) {
                try {
                    Page tempPage = ctx.newPage();
                    try {
                        tempPage.navigate("chrome://extensions");
                        tempPage.click("cr-toggle#devMode");
                        Locator extensionCard = tempPage.locator("extensions-item").first();
                        extId = extensionCard.getAttribute("id");

                        if (extId != null) {
                            api.logging().logToOutput("Found extension ID from chrome://extensions: " + extId);
                        }
                    } catch (Exception e) {
                        api.logging().logToOutput("Could not access chrome://extensions: " + e.getMessage());
                    }
                    tempPage.close();
                } catch (Exception e) {
                    api.logging().logToOutput("Error detecting extension ID: " + e.getMessage());
                }

                if (extId == null) {
                    api.logging().logToError("Could not detect extension ID, extension features will not be configured");
                }
            }

            if (extId != null) {
                try {
                    Page extPage = ctx.newPage();
                    extPage.navigate("chrome-extension://" + extId + "/settings/settings.html");
                    extPage.evaluate(domInvaderConfig.generateSettingsScript());
                    api.logging().logToOutput("Configured extension settings");
                    extPage.close();
                } catch (Exception e) {
                    api.logging().logToError("Error configuring extension: " + e.getMessage());
                }
            }

            Page page = ctx.newPage();

            for (String url : urls) {
                try {
                    ctx.exposeBinding("sendToBurp", (source, arguments) -> {
                        String frameUrl = source.frame().url();
                        if (!frameUrl.startsWith(url)) throw new RuntimeException("blocked");
                        if (arguments.length != 2 || !(arguments[0] instanceof String payload)) throw new RuntimeException("bad args");
                        String json = arguments[0].toString();
                        String type = arguments[1].toString();
                        api.logging().logToOutput("JSON:" + json);
                        api.logging().logToOutput("type:" + type);
                        return "ack:" + payload;
                    });
                    page.navigate(url, new Page.NavigateOptions().setWaitUntil(WaitUntilState.NETWORKIDLE));

                    // Wait for DOM Invader to complete
                    api.logging().logToOutput("Waiting for DOM Invader to complete analysis for: " + url);
                    page.waitForFunction(
                            "() => window.BurpDOMInvader && window.BurpDOMInvader.isComplete",
                            null,
                            new Page.WaitForFunctionOptions().setPollingInterval(100).setTimeout(30000)
                    );
                    api.logging().logToOutput("DOM Invader analysis complete for: " + url);
                } catch (Exception e) {
                    api.logging().logToError("Failed to load URL: " + url + " - " + e.getMessage());
                }
            }

            if (closeBrowser) {
                ctx.close();
                playwright.close();
            }
        } catch (Exception e) {
            api.logging().logToError("Error in Playwright rendering: " + e.getMessage());
            if (ctx != null) {
                ctx.close();
            }
            if (playwright != null) {
                playwright.close();
            }
        }
    }

    public static String getBurpChromiumPath() {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("mac")) {
                String basePath = "/Applications/Burp Suite Professional.app/Contents/Resources/app/burpbrowser/";
                Process p = new ProcessBuilder("sh", "-c",
                    "ls '" + basePath + "' | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | head -1")
                    .start();
                String version = new String(p.getInputStream().readAllBytes()).trim();
                p.waitFor();

                if (!version.isEmpty()) {
                    return basePath + version + "/Chromium.app/Contents/MacOS/Chromium";
                }

            } else if (os.contains("win")) {
                String basePath = System.getProperty("user.home") + "\\AppData\\Local\\Programs\\BurpSuitePro\\burpbrowser\\";
                Process p = new ProcessBuilder("cmd", "/c",
                    "dir /B \"" + basePath + "\" | findstr /R \"^[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*\\.[0-9][0-9]*$\"")
                    .start();
                String version = new String(p.getInputStream().readAllBytes()).trim();
                p.waitFor();

                if (!version.isEmpty()) {
                    return basePath + version + "\\chrome.exe";
                }

            } else { // Linux
                String basePath = System.getProperty("user.home") + "/.BurpSuite/burpbrowser/";
                Process p = new ProcessBuilder("sh", "-c",
                    "ls '" + basePath + "' 2>/dev/null | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | head -1")
                    .start();
                String version = new String(p.getInputStream().readAllBytes()).trim();
                p.waitFor();

                if (!version.isEmpty()) {
                    return basePath + version + "/chrome";
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error finding Burp Chromium path: " + e.getMessage());
        }

        return "";
    }
}