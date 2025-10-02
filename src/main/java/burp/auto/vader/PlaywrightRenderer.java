package burp.auto.vader;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.WaitUntilState;

import java.io.File;
import java.nio.file.Paths;
import java.util.List;

import static burp.auto.vader.AutoVaderExtension.*;

public class PlaywrightRenderer {

    private final String sinkCallback = """
        function(sinkDetails, sinks, interestingSinks) {
            const payload = {
                isInteresting: sinkDetails.isInteresting,
                canary: sinkDetails.canary,
                sink: sinkDetails.sink,
                stackTrace: sinkDetails.stackTrace,
                value: sinkDetails.value,
                url: sinkDetails.url,
                framePath: sinkDetails.framePath,
                event: sinkDetails.event,
                outerHTML: sinkDetails.outerHTML
            };
        
            sendToBurp(payload,"sink");
            return true; // return true to log sink
        }
    """;

    private final String sourceCallback = """
        function(sourceDetails, sources) {
            const payload = {
                isInteresting: sourceDetails.isInteresting,
                canary: sourceDetails.canary,
                source: sourceDetails.source,
                stackTrace: sourceDetails.stackTrace,
                value: sourceDetails.value,
                url: sourceDetails.url,
                framePath: sourceDetails.framePath,
                event: sourceDetails.event
            };
        
            sendToBurp(payload, "source");
            return true; // return true to log source
        }
    """;

    private final String messageCallback = """
        function(msg) {
            const payload = {
                isInteresting: msg.isInteresting,
                canary: msg.canary,
                id: msg.id,
                title: msg.title,
                description: msg.description,
                url: msg.url,
                charactersEncoded: msg.charactersEncoded,
                confidence: msg.confidence,
                dataAccessed: msg.dataAccessed,
                dataStackTrace: msg.dataStackTrace,
                eventListener: msg.eventListener,
                eventListenerStack: msg.eventListenerStack,
                followupVerified: msg.followupVerified,
                manipulatedData: msg.manipulatedData,
                messageType: msg.messageType,
                origin: msg.origin,
                originChecked: msg.originChecked,
                originCheckedFirst: msg.originCheckedFirst,
                originStackTrace: msg.originStackTrace,
                originalOrigin: msg.originalOrigin,
                postMessageData: msg.postMessageData,
                severity: msg.severity,
                sink: msg.sink,
                sinkValue: msg.sinkValue,
                sourceAccessed: msg.sourceAccessed,
                sourceId: msg.sourceId,
                spoofed: msg.spoofed,
                verified: msg.verified,
                framePathFrom: msg.framePathFrom,
                framePathTo: msg.framePathTo
            };
        
            sendToBurp(payload, "message");
            return true; // return true to log message
        }
    """;

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
                // Try to get extension ID by checking the Extension State directory
                try {
                    // Check for Extensions directory which contains subdirectories named by extension ID
                    File extensionsDir = new File(userDataDir, "Default/Extensions");
                    api.logging().logToOutput("Looking for Extensions directory at: " + extensionsDir.getAbsolutePath());

                    if (!extensionsDir.exists()) {
                        extensionsDir = new File(userDataDir, "Extensions");
                        api.logging().logToOutput("Trying alternate Extensions directory at: " + extensionsDir.getAbsolutePath());
                    }

                    if (extensionsDir.exists() && extensionsDir.isDirectory()) {
                        File[] extensionDirs = extensionsDir.listFiles(File::isDirectory);
                        if (extensionDirs != null && extensionDirs.length > 0) {
                            // Get the first extension ID (assumes only one extension is loaded)
                            for (File dir : extensionDirs) {
                                String dirName = dir.getName();
                                // Extension IDs are 32 lowercase letters
                                if (dirName.matches("[a-z]{32}")) {
                                    extId = dirName;
                                    api.logging().logToOutput("Found extension ID from Extensions directory: " + extId);
                                    break;
                                }
                            }
                        }
                    }

                    // Fallback: Check Preferences file
                    if (extId == null) {
                        File prefsFile = new File(userDataDir, "Preferences");
                        if (!prefsFile.exists()) {
                            prefsFile = new File(userDataDir, "Default/Preferences");
                        }

                        if (prefsFile.exists()) {
                            String prefsContent = java.nio.file.Files.readString(prefsFile.toPath());
                            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"([a-z]{32})\"");
                            java.util.regex.Matcher matcher = pattern.matcher(prefsContent);
                            if (matcher.find()) {
                                extId = matcher.group(1);
                                api.logging().logToOutput("Found extension ID in preferences: " + extId);
                            }
                        }
                    }
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
                    extPage.evaluate("""
                        () => {
                            chrome.storage.local.set({
                                canary: 'burpdomxss',
                                sinkCallback: "function(){console.log(sendToBurp('Hello').then(m=>m));return true;}"
                            });
                        }
                    """);
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
                        if (arguments.length != 1 || !(arguments[0] instanceof String payload)) throw new RuntimeException("bad args");
                        return "ack:" + payload;
                    });

                    page.navigate(url, new Page.NavigateOptions().setWaitUntil(WaitUntilState.NETWORKIDLE));
                    page.reload();
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

        // Fallback to empty string if not found
        return "";
    }
}