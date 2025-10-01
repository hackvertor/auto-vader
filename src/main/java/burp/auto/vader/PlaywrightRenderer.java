package burp.auto.vader;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.WaitUntilState;

import java.io.File;
import java.nio.file.Paths;
import java.util.List;

import static burp.auto.vader.AutoVaderExtension.*;

public class PlaywrightRenderer {

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
                            chrome.storage.local.set({canary: 'foobar'});
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
                    page.navigate(url, new Page.NavigateOptions()
                            .setWaitUntil(WaitUntilState.NETWORKIDLE));
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