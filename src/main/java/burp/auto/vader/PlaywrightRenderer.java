package burp.auto.vader;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.Proxy;
import com.microsoft.playwright.options.WaitUntilState;

import java.nio.file.Paths;
import java.util.List;

import static burp.auto.vader.AutoVaderExtension.api;
import static burp.auto.vader.AutoVaderExtension.chromiumPath;

public class PlaywrightRenderer {

    public void renderUrls(List<String> urls, String extensionPath) {
        try (Playwright playwright = Playwright.create()) {
            BrowserType.LaunchOptions launchOptions = new BrowserType.LaunchOptions();

            if (!chromiumPath.isEmpty()) {
                launchOptions.setExecutablePath(Paths.get(chromiumPath));
                api.logging().logToOutput("Using Burp Chromium at: " + chromiumPath);
            } else {
                api.logging().logToOutput("Burp Chromium not found, using system browser");
            }

            if (extensionPath != null && !extensionPath.isEmpty()) {
                launchOptions.setArgs(java.util.Arrays.asList(
                        "--disable-extensions-except=" + extensionPath,
                        "--load-extension=" + extensionPath
                )).setHeadless(false);
            }

            Browser browser = playwright.chromium().launch(launchOptions);
            BrowserContext context = browser.newContext();
            Page page = context.newPage();

            for (String url : urls) {
                try {
                    page.navigate(url, new Page.NavigateOptions()
                            .setWaitUntil(WaitUntilState.NETWORKIDLE));
                } catch (Exception e) {
                    api.logging().logToError("Failed to load URL: " + url + " - " + e.getMessage());
                }
            }

            browser.close();
        } catch (Exception e) {
            api.logging().logToError("Error in Playwright rendering: " + e.toString());
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