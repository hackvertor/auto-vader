package burp.auto.vader;

import com.google.gson.Gson;
import com.microsoft.playwright.*;
import com.microsoft.playwright.options.WaitUntilState;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
    private boolean shouldOpenDevtools = false;
    private final DOMInvaderConfig domInvaderConfig;
    private final DOMInvaderIssueReporter issueReporter;
    public PlaywrightRenderer( IssueDeduplicator dedupe, boolean shouldOpenDevtools) {
        this(new DOMInvaderConfig(), dedupe, shouldOpenDevtools);
    }

    public PlaywrightRenderer(DOMInvaderConfig domInvaderConfig, IssueDeduplicator deduper, boolean shouldOpenDevtools) {
        this.domInvaderConfig = domInvaderConfig;
        this.issueReporter = new DOMInvaderIssueReporter(api, deduper);
        this.shouldOpenDevtools = shouldOpenDevtools;
    }

    public void renderUrls(List<String> urls, String extensionPath, boolean closeBrowser, boolean headless, boolean shouldSendToBurp) {
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
                List<String> args = new ArrayList<>();
                args.add("--disable-extensions-except=" + extensionPath);
                args.add("--load-extension=" + extensionPath);
                if (shouldOpenDevtools) {
                    args.add("--auto-open-devtools-for-tabs");
                }
                launchOptions.setArgs(args).setHeadless(headless);
            } else {
                launchOptions.setHeadless(headless);
            }

            ctx = playwright.chromium().launchPersistentContext(Paths.get(userDataDir), launchOptions);
            String extId = null;
            Page page = ctx.pages().getFirst();
            if (extensionPath != null && !extensionPath.isEmpty()) {
                try {
                    try {
                        page.navigate("chrome://extensions");
                        page.click("cr-toggle#devMode");
                        Locator extensionCard = page.locator("extensions-item").first();
                        extId = extensionCard.getAttribute("id");

                        if (extId != null) {
                            api.logging().logToOutput("Found extension ID from chrome://extensions: " + extId);
                        }
                    } catch (Exception e) {
                        api.logging().logToOutput("Could not access chrome://extensions: " + e.getMessage());
                    }
                } catch (Exception e) {
                    api.logging().logToOutput("Error detecting extension ID: " + e.getMessage());
                }

                if (extId == null) {
                    api.logging().logToError("Could not detect extension ID, extension features will not be configured");
                }
            }
            page.onConsoleMessage(msg -> api.logging().logToOutput(msg.text()));
            if (extId != null) {
                try {
                    page.navigate("chrome-extension://" + extId + "/settings/settings.html");
                    page.evaluate(domInvaderConfig.generateSettingsScript());
                    api.logging().logToOutput("Configured extension settings");
                } catch (Exception e) {
                    api.logging().logToError("Error configuring extension: " + e.getMessage());
                }
            }

            ctx.exposeBinding("sendToBurp", (source, arguments) -> {
                String frameUrl = source.frame().url();
                if (arguments.length != 2) throw new RuntimeException("bad args");

                Gson gson = new Gson();
                String json = gson.toJson(arguments[0]);
                String type = arguments[1].toString();

                if(shouldSendToBurp) {
                    issueReporter.parseAndReport(json, type, frameUrl);
                }
                return null;
            });

            if(settings.getBoolean("Remove CSP")) {
                page.route("**/*", route -> {
                    var response = route.fetch();

                    Map<String, String> headers = new HashMap<>(response.headers());

                    headers.entrySet().removeIf(entry -> {
                        String key = entry.getKey().toLowerCase();
                        return key.equals("content-security-policy");
                    });

                    route.fulfill(new Route.FulfillOptions()
                            .setResponse(response)
                            .setHeaders(headers));
                });
            }

            for (String url : urls) {
                try {
                    page.navigate(url, new Page.NavigateOptions().setWaitUntil(WaitUntilState.NETWORKIDLE));
                    page.reload();
                    api.logging().logToOutput("Waiting for DOM Invader to complete analysis for: " + url);
                    page.waitForFunction(
                            "() => window.BurpDOMInvader && window.BurpDOMInvader.isComplete",
                            null,
                            new Page.WaitForFunctionOptions().setPollingInterval(100).setTimeout(30000)
                    );
                    api.logging().logToOutput("DOM Invader analysis complete for: " + url);
                } catch (Throwable e) {
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