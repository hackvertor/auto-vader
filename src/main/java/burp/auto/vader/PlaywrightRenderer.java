package burp.auto.vader;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.Gson;
import com.microsoft.playwright.*;
import com.microsoft.playwright.options.RequestOptions;
import com.microsoft.playwright.options.WaitUntilState;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

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
    private IssueDeduplicator issueDeduplicator;
    public PlaywrightRenderer( IssueDeduplicator dedupe, boolean shouldOpenDevtools) {
        this(new DOMInvaderConfig(), dedupe, shouldOpenDevtools);
    }

    public PlaywrightRenderer(DOMInvaderConfig domInvaderConfig, IssueDeduplicator deduper, boolean shouldOpenDevtools) {
        boolean shouldAlwaysOpenDevtools = settings.getBoolean("Always open devtools");
        this.domInvaderConfig = domInvaderConfig;
        this.shouldOpenDevtools = shouldOpenDevtools || shouldAlwaysOpenDevtools;
        this.issueDeduplicator = deduper;
    }

    public static class BrowserSession {
        public final Playwright playwright;
        public final BrowserContext ctx;
        public final Page page;
        public DOMInvaderIssueReporter issueReporter; // Mutable to allow updating

        public BrowserSession(Playwright playwright, BrowserContext ctx, Page page, DOMInvaderIssueReporter issueReporter) {
            this.playwright = playwright;
            this.ctx = ctx;
            this.page = page;
            this.issueReporter = issueReporter;
        }
    }

    private boolean fileExists(String filePath) {
        Path path = Paths.get(filePath);
        return Files.exists(path);
    }

    private boolean directoryExists(String directory) {
        Path path = Paths.get(directory);
        return Files.exists(path) && Files.isDirectory(path);
    }

    private BrowserSession initializeBrowser(String extensionPath, boolean headless, boolean shouldSendToBurp, DOMInvaderIssueReporter initialReporter) throws Exception {
        String homeDir = System.getProperty("user.home");
        File autoVaderDir = new File(homeDir, ".AutoVader");
        if (!autoVaderDir.exists()) {
            autoVaderDir.mkdirs();
            api.logging().logToOutput("Created AutoVader directory at: " + autoVaderDir.getAbsolutePath());
        }

        Playwright playwright = Playwright.create();
        BrowserType.LaunchPersistentContextOptions launchOptions = new BrowserType.LaunchPersistentContextOptions();
        String chromiumPath = AutoVaderExtension.chromiumPath.isEmpty() ? settings.getString("Path to Burp Chromium") : AutoVaderExtension.chromiumPath;
        if (fileExists(chromiumPath)) {
            launchOptions.setExecutablePath(Paths.get(chromiumPath));
            api.logging().logToOutput("Using Burp Chromium at: " + chromiumPath);
        } else {
            api.logging().logToError("Burp Chromium not found, try changing Settings->Extensions->AutoVader->Path to Burp Chromium");
            throw new RuntimeException("Burp Chromium not found");
        }

        String userDataDir = new File(autoVaderDir, "browser-profile").getAbsolutePath();

        if(!directoryExists(extensionPath)) {
            extensionPath = settings.getString("Path to DOM Invader");
            if(!directoryExists(extensionPath)) {
                api.logging().logToError("DOM Invader not found, try changing Settings->Extensions->AutoVader->Path to DOM Invader");
                throw new RuntimeException("DOM Invader not found");
            }
        }

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

        BrowserContext ctx = playwright.chromium().launchPersistentContext(Paths.get(userDataDir), launchOptions);
        Page page = ctx.pages().getFirst();

        // Create the browser session early so we can reference it in the binding
        BrowserSession session = new BrowserSession(playwright, ctx, page, initialReporter);

        // Configure extension if present
        String extId = detectAndConfigureExtension(page, extensionPath);

        // Set up page handlers
        page.onConsoleMessage(msg -> api.logging().logToOutput(msg.text()));

        // Configure DOM Invader settings if extension detected
        if (extId != null) {
            try {
                page.navigate("chrome-extension://" + extId + "/settings/settings.html");
                page.evaluate(domInvaderConfig.generateSettingsScript());
                api.logging().logToOutput("Configured extension settings");
            } catch (Exception e) {
                api.logging().logToError("Error configuring extension: " + e.getMessage());
            }
        }

        // Set up sendToBurp binding - use reference to session's issueReporter
        ctx.exposeBinding("sendToBurp", (source, arguments) -> {
            // Use the current issueReporter from the session (can be updated)
            DOMInvaderIssueReporter currentReporter = session.issueReporter;
            if (currentReporter == null || currentReporter.getRequest() == null) {
                api.logging().logToError("No issue reporter or request available");
                return null;
            }

            String scannedUrl = currentReporter.getRequest().url();
            String frameUrl = source.frame().url();
            boolean isValidOrigin;
            try {
                isValidOrigin = getOrigin(frameUrl).equalsIgnoreCase(getOrigin(scannedUrl));
            } catch (URISyntaxException | IllegalArgumentException e) {
                isValidOrigin = false;
            }
            if(!isValidOrigin && !api.scope().isInScope(frameUrl)) {
                api.logging().logToError("Invalid source when sending to Burp");
                api.logging().logToError("Source:" + frameUrl);
                api.logging().logToError("Scanned URL:" + scannedUrl);
                return null;
            }
            if (arguments.length != 2) throw new RuntimeException("bad args");
            Gson gson = new Gson();
            String json = gson.toJson(arguments[0]);
            String type = arguments[1].toString();

            if(shouldSendToBurp) {
                currentReporter.parseAndReport(json, type, currentReporter.getRequest());
            }
            return null;
        });

        // Set up CSP removal if configured
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

        return session;
    }

    private String detectAndConfigureExtension(Page page, String extensionPath) {
        if (extensionPath == null || extensionPath.isEmpty()) {
            return null;
        }

        String extId = null;
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
                api.logging().logToError("Could not access chrome://extensions: " + e.getMessage());
            }
        } catch (Exception e) {
            api.logging().logToError("Error detecting extension ID: " + e.getMessage());
        }

        if (extId == null) {
            api.logging().logToError("Could not detect extension ID, extension features will not be configured");
        }

        return extId;
    }

    private void waitForDomInvader(Page page, String url) {
        try {
            api.logging().logToOutput("Waiting for DOM Invader to complete analysis for: " + url);
            page.waitForFunction(
                    "() => window.BurpDOMInvader && window.BurpDOMInvader.isComplete",
                    null,
                    new Page.WaitForFunctionOptions().setPollingInterval(100).setTimeout(30000)
            );
            api.logging().logToOutput("DOM Invader analysis complete for: " + url);
        } catch (Exception e) {
            if(api == null) return;
            api.logging().logToError("DOM Invader wait failed for: " + url + " - " + e.getMessage());
        }
    }

    public void renderUrls(List<String> urls, String extensionPath, boolean closeBrowser, boolean headless, boolean shouldSendToBurp, int delay) {
        BrowserSession session = null;
        try {
            DOMInvaderIssueReporter issueReporter = new DOMInvaderIssueReporter(api, issueDeduplicator);
            session = initializeBrowser(extensionPath, headless, shouldSendToBurp, issueReporter);

            for (String url : urls) {
                if(!url.startsWith("http://") && !url.startsWith("https://")) continue;
                try {
                    issueReporter.setRequest(HttpRequest.httpRequestFromUrl(url));
                    //horrible hack because for some reason DOM Invader settings are not synchronised on the first request
                    session.page.navigate(url, new Page.NavigateOptions().setWaitUntil(WaitUntilState.NETWORKIDLE));
                    if(delay > 0) {
                        Thread.sleep(delay);
                    }
                    session.page.navigate(url, new Page.NavigateOptions().setWaitUntil(WaitUntilState.NETWORKIDLE));
                    if(delay > 0) {
                        Thread.sleep(delay);
                    }
                    waitForDomInvader(session.page, url);
                } catch (Throwable e) {
                    api.logging().logToError("Failed to load URL: " + url + " - " + e.getMessage());
                }
            }

            if (closeBrowser) {
                session.ctx.close();
                session.playwright.close();
            }
        } catch (Throwable e) {
            api.logging().logToError("Error in Playwright rendering: " + e.getMessage());
            if (session != null) {
                if (session.ctx != null) {
                    session.ctx.close();
                }
                if (session.playwright != null) {
                    session.playwright.close();
                }
            }
        }
    }

    public void renderHttpRequests(List<HttpRequest> requests, String extensionPath, boolean closeBrowser, boolean headless, boolean shouldSendToBurp, int delay) {
        BrowserSession session = null;
        try {
            DOMInvaderIssueReporter issueReporter = new DOMInvaderIssueReporter(api, issueDeduplicator);
            session = initializeBrowser(extensionPath, headless, shouldSendToBurp, issueReporter);

            // Process each HttpRequest
            for (HttpRequest burpReq : requests) {
                issueReporter.setRequest(burpReq);
                try {
                    String url = burpReq.url();
                    if(!url.startsWith("http://") && !url.startsWith("https://")) continue;
                    String method = burpReq.method();

                    // Create request options
                    RequestOptions opts = RequestOptions.create().setMethod(method);

                    // Set headers from Burp request
                    for (HttpHeader h : burpReq.headers()) {
                        // Skip content-length as it will be calculated automatically
                        if (!h.name().equalsIgnoreCase("content-length")) {
                            opts.setHeader(h.name(), h.value());
                        }
                    }

                    // Set body data if present
                    String body = burpReq.bodyToString();
                    if (body != null && !body.isEmpty()) {
                        opts.setData(body);
                    }

                    // Make the request using context
                    APIResponse response = session.ctx.request().fetch(url, opts);
                    // Navigate to the response URL to render it in the browser

                    String stub = response.url();
                    session.page.route(stub, route -> route.fulfill(
                            new Route.FulfillOptions()
                                    .setStatus(response.status())
                                    .setHeaders(response.headers())
                                    .setBodyBytes(response.body())
                    ));
                    session.page.navigate(stub, new Page.NavigateOptions().setWaitUntil(WaitUntilState.NETWORKIDLE));
                    if(delay > 0) {
                        Thread.sleep(delay);
                    }
                    session.page.navigate(stub, new Page.NavigateOptions().setWaitUntil(WaitUntilState.NETWORKIDLE));
                    if(delay > 0) {
                        Thread.sleep(delay);
                    }
                    waitForDomInvader(session.page, url);
                } catch (Throwable e) {
                    api.logging().logToError("Failed to process request: " + burpReq.url() + " - " + e.getMessage());
                }
            }

            if (closeBrowser) {
                session.ctx.close();
                session.playwright.close();
            }
        } catch (Exception e) {
            api.logging().logToError("Error in Playwright rendering: " + e.getMessage());
            if (session != null) {
                if (session.ctx != null) {
                    session.ctx.close();
                }
                if (session.playwright != null) {
                    session.playwright.close();
                }
            }
        }
    }

    /**
     * Render HTTP requests using an existing browser session.
     * This method does not close the browser after completion.
     */
    public void renderHttpRequestsWithSession(List<HttpRequest> requests, BrowserSession session, int delay) {
        if (session == null) {
            api.logging().logToError("Browser session is null");
            return;
        }

        // Create a new issue reporter for this batch of requests
        DOMInvaderIssueReporter issueReporter = new DOMInvaderIssueReporter(api, issueDeduplicator);

        // Update the session's issue reporter so the binding uses the current one
        session.issueReporter = issueReporter;

        // Process each HttpRequest
        for (HttpRequest burpReq : requests) {
            issueReporter.setRequest(burpReq);
            try {
                String url = burpReq.url();
                if(!url.startsWith("http://") && !url.startsWith("https://")) continue;
                String method = burpReq.method();

                // Create request options
                RequestOptions opts = RequestOptions.create().setMethod(method);

                // Set headers from Burp request
                for (HttpHeader h : burpReq.headers()) {
                    // Skip content-length as it will be calculated automatically
                    if (!h.name().equalsIgnoreCase("content-length")) {
                        opts.setHeader(h.name(), h.value());
                    }
                }

                // Set body data if present
                String body = burpReq.bodyToString();
                if (body != null && !body.isEmpty()) {
                    opts.setData(body);
                }

                // Make the request using context
                APIResponse response = session.ctx.request().fetch(url, opts);
                // Navigate to the response URL to render it in the browser

                String stub = response.url();
                session.page.route(stub, route -> route.fulfill(
                        new Route.FulfillOptions()
                                .setStatus(response.status())
                                .setHeaders(response.headers())
                                .setBodyBytes(response.body())
                ));
                session.page.navigate(stub, new Page.NavigateOptions().setWaitUntil(WaitUntilState.NETWORKIDLE));
                if(delay > 0) {
                    Thread.sleep(delay);
                }
                session.page.navigate(stub, new Page.NavigateOptions().setWaitUntil(WaitUntilState.NETWORKIDLE));
                if(delay > 0) {
                    Thread.sleep(delay);
                }
                waitForDomInvader(session.page, url);
            } catch (Throwable e) {
                api.logging().logToError("Failed to process request: " + burpReq.url() + " - " + e.getMessage());
            }
        }
    }

    /**
     * Initialize a browser session that can be reused.
     * The caller is responsible for closing this session.
     */
    public BrowserSession createBrowserSession(String extensionPath, boolean headless, boolean shouldSendToBurp) throws Exception {
        DOMInvaderIssueReporter issueReporter = new DOMInvaderIssueReporter(api, issueDeduplicator);
        return initializeBrowser(extensionPath, headless, shouldSendToBurp, issueReporter);
    }

    /**
     * Close a browser session.
     */
    public void closeBrowserSession(BrowserSession session) {
        if (session != null) {
            try {
                if (session.ctx != null) {
                    session.ctx.close();
                }
                if (session.playwright != null) {
                    session.playwright.close();
                }
            } catch (Exception e) {
                api.logging().logToError("Error closing browser session: " + e.getMessage());
            }
        }
    }

    /**
     * Check if a browser session is still valid.
     */
    public boolean isBrowserSessionValid(BrowserSession session) {
        if (session == null || session.page == null || session.ctx == null) {
            return false;
        }

        try {
            // Try to evaluate a simple expression to check if the page is responsive
            session.page.evaluate("1 + 1");
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private  String getOrigin(String url) throws URISyntaxException {
        URI uri = new URI(url);
        String scheme = uri.getScheme();
        String host = uri.getHost();
        int port = uri.getPort();

        if (scheme == null || host == null) {
            throw new IllegalArgumentException("Invalid URL: " + url);
        }

        if (port == -1) {
            return scheme + "://" + host;
        } else {
            return scheme + "://" + host + ":" + port;
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