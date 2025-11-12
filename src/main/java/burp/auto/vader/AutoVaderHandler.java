package burp.auto.vader;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.auto.vader.actions.AutoVaderActions;

import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import static burp.auto.vader.AutoVaderExtension.*;
import static burp.auto.vader.actions.AutoVaderActions.createScanProfile;

public class AutoVaderHandler implements HttpHandler {
    private static PlaywrightRenderer.BrowserSession browserSession;
    private static PlaywrightRenderer rendererInstance;
    private static final ReentrantLock sessionLock = new ReentrantLock();

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        boolean isFromRepeater = req.toolSource().isFromTool(ToolType.REPEATER);
        boolean isFromIntruder = req.toolSource().isFromTool(ToolType.INTRUDER);
        boolean isFromExtensions = req.toolSource().isFromTool(ToolType.EXTENSIONS);
        boolean shouldRunFromRepeater = settings.getBoolean("Auto run from Repeater");
        boolean shouldRunFromIntruder = settings.getBoolean("Auto run from Intruder");
        boolean shouldRunFromOtherExtensions = settings.getBoolean("Auto run from other extensions");

        boolean shouldExecute = (shouldRunFromRepeater && isFromRepeater) ||
                                (shouldRunFromIntruder && isFromIntruder) ||
                                (shouldRunFromOtherExtensions && isFromExtensions);

        if(shouldExecute) {
            executorService.submit(
              () -> {
                String domInvaderPath = AutoVaderExtension.domInvaderPath;
                String canary = projectCanary;
                if (!req.isInScope()) return;
                String reqStr = req.toString();
                if(!reqStr.contains("$canary")) return;
                reqStr = reqStr.replace("$canary", canary);
                boolean isHeadless = settings.getBoolean("Headless");
                DOMInvaderConfig.Profile profile =
                    createScanProfile(canary, AutoVaderActions.ScanType.QUERY_PARAMS);
                int delay = settings.getInteger("Delay MS");

                // Use the persistent browser session
                sessionLock.lock();
                try {
                    // Initialize renderer instance if not already created
                    if (rendererInstance == null) {
                        rendererInstance = new PlaywrightRenderer(new DOMInvaderConfig(profile), deduper, false);
                    }

                    // Check if browser session is valid, create new one if needed
                    if (browserSession == null || !rendererInstance.isBrowserSessionValid(browserSession)) {
                        // Close old session if it exists but is invalid
                        if (browserSession != null) {
                            try {
                                rendererInstance.closeBrowserSession(browserSession);
                            } catch (Exception e) {
                                api.logging().logToError("Error closing invalid browser session: " + e.getMessage());
                            }
                        }

                        // Create new browser session
                        try {
                            api.logging().logToOutput("Creating new browser session for HttpHandler");
                            browserSession = rendererInstance.createBrowserSession(domInvaderPath, isHeadless, true);
                        } catch (Exception e) {
                            api.logging().logToError("Failed to create browser session: " + e.getMessage());
                            return;
                        }
                    }

                    // Use the existing session to render the request
                    rendererInstance.renderHttpRequestsWithSession(
                        List.of(HttpRequest.httpRequest(req.httpService(), reqStr)),
                        browserSession,
                        delay
                    );
                } finally {
                    sessionLock.unlock();
                }
              });
        }
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        return null;
    }

    /**
     * Closes the persistent browser session.
     * This should be called when the extension is being unloaded or when the user wants to close the browser.
     */
    public static void closePersistentBrowser() {
        sessionLock.lock();
        try {
            if (browserSession != null && rendererInstance != null) {
                api.logging().logToOutput("Closing persistent browser session for HttpHandler");
                rendererInstance.closeBrowserSession(browserSession);
                browserSession = null;
            }
        } catch (Exception e) {
            api.logging().logToError("Error closing persistent browser: " + e.getMessage());
        } finally {
            sessionLock.unlock();
        }
    }

    /**
     * Force reopens the browser session, closing any existing session first.
     */
    public static void reopenBrowser() {
        sessionLock.lock();
        try {
            closePersistentBrowser();
            // The browser will be recreated on the next request
            api.logging().logToOutput("Browser session closed. A new session will be created on the next request.");
        } finally {
            sessionLock.unlock();
        }
    }

    /**
     * Get or create the singleton browser session.
     * This allows other components to reuse the same browser session.
     * @return The browser session or null if creation fails
     */
    public static PlaywrightRenderer.BrowserSession getOrCreateBrowserSession() {
        sessionLock.lock();
        try {
            String domInvaderPath = AutoVaderExtension.domInvaderPath;
            boolean isHeadless = settings.getBoolean("Headless");
            String canary = projectCanary;

            // Initialize renderer instance if not already created
            if (rendererInstance == null) {
                DOMInvaderConfig.Profile profile =
                    createScanProfile(canary, AutoVaderActions.ScanType.QUERY_PARAMS);
                rendererInstance = new PlaywrightRenderer(new DOMInvaderConfig(profile), deduper, false);
            }

            // Check if browser session is valid, create new one if needed
            if (browserSession == null || !rendererInstance.isBrowserSessionValid(browserSession)) {
                // Close old session if it exists but is invalid
                if (browserSession != null) {
                    try {
                        rendererInstance.closeBrowserSession(browserSession);
                    } catch (Exception e) {
                        api.logging().logToError("Error closing invalid browser session: " + e.getMessage());
                    }
                }

                // Create new browser session
                try {
                    api.logging().logToOutput("Creating new browser session for shared use");
                    browserSession = rendererInstance.createBrowserSession(domInvaderPath, isHeadless, true);
                } catch (Exception e) {
                    api.logging().logToError("Failed to create browser session: " + e.getMessage());
                    return null;
                }
            }

            return browserSession;
        } finally {
            sessionLock.unlock();
        }
    }

    /**
     * Get the renderer instance
     * @return The renderer instance or null if not initialized
     */
    public static PlaywrightRenderer getRendererInstance() {
        return rendererInstance;
    }
}
