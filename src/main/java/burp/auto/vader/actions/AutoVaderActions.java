package burp.auto.vader.actions;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.auto.vader.*;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static burp.auto.vader.AutoVaderExtension.*;

/**
 * Shared actions for both context menu items and hotkeys
 */
public class AutoVaderActions {

    private final IssueDeduplicator deduper;

    public enum ScanType {
        WEB_MESSAGE,
        QUERY_PARAMS,
        POST_PARAMS,
        CLIENT_SIDE_PROTOTYPE_POLLUTION,
        CLIENT_SIDE_PROTOTYPE_POLLUTION_GADGETS,
        INJECT_INTO_ALL_SOURCES,
        INJECT_INTO_ALL_SOURCES_AND_CLICK
    }

    public interface ScanProcessor {
        List<String> processUrls(List<String> urls, String canary);
    }

    public interface PostScanProcessor {
        List<HttpRequest> processRequests(List<HttpRequestResponse> requestResponses, String canary);
    }

    public AutoVaderActions(IssueDeduplicator deduper) {
        this.deduper = deduper;
    }

    /**
     * Open DOM Invader for a single URL
     */
    public void openDOMInvader(String url) {
        executorService.submit(() -> {
            String domInvaderPath = AutoVaderExtension.domInvaderPath;
            int delay = settings.getInteger("Delay MS");
            new PlaywrightRenderer(new DOMInvaderConfig(DOMInvaderConfig.customProfile(projectCanary)), deduper, true)
                    .renderUrls(Collections.singletonList(url), domInvaderPath, false, false, false, delay);
        });
    }

    /**
     * Scan all GET parameters
     */
    public void scanAllQueryParameters(List<String> urls) {
        executeScan(urls, (urlList, canary) -> {
            String payload = settings.getString("Payload");
            List<String> enumeratedUrls = Utils.enumerateQueryParameters(urlList, canary, payload);
            api.logging().logToOutput("Urls:" + enumeratedUrls);
            if (enumeratedUrls.isEmpty()) {
                api.logging().logToOutput("No query parameters found to scan");
            }
            return enumeratedUrls;
        }, ScanType.QUERY_PARAMS);
    }

    /**
     * Scan all POST parameters
     */
    public void scanAllPostParameters(List<HttpRequestResponse> requestResponses) {
        executeScanForPosts(requestResponses, (requests, canary) -> {
            String payload = settings.getString("Payload");
            List<HttpRequest> enumeratedRequests = Utils.enumeratePostParameters(requests, canary, payload);
            api.logging().logToOutput("Requests: " + enumeratedRequests.size());
            if (enumeratedRequests.isEmpty()) {
                api.logging().logToOutput("No POST parameters found to scan");
            }
            return enumeratedRequests;
        }, ScanType.POST_PARAMS);
    }

    /**
     * Scan web messages
     */
    public void scanWebMessages(List<String> urls) {
        executeScan(urls, (urlList, canary) -> urlList, ScanType.WEB_MESSAGE);
    }

    /**
     * Inject into all sources
     */
    public void injectIntoAllSources(List<String> urls) {
        executeScan(urls, (urlList, canary) -> urlList, ScanType.INJECT_INTO_ALL_SOURCES);
    }

    /**
     * Inject into all sources and click everything
     */
    public void injectIntoAllSourcesAndClick(List<String> urls) {
        executeScan(urls, (urlList, canary) -> urlList, ScanType.INJECT_INTO_ALL_SOURCES_AND_CLICK);
    }

    /**
     * Scan for client side prototype pollution
     */
    public void scanPrototypePollution(List<String> urls) {
        executeScan(urls, (urlList, canary) -> urlList, ScanType.CLIENT_SIDE_PROTOTYPE_POLLUTION);
    }

    /**
     * Scan for client side prototype pollution gadgets
     */
    public void scanPrototypePollutionGadgets(List<String> urls) {
        executeScan(urls, (urlList, canary) -> urlList, ScanType.CLIENT_SIDE_PROTOTYPE_POLLUTION_GADGETS);
    }

    /**
     * Intercept client side redirect
     */
    public void interceptClientSideRedirect(String url) {
        executorService.submit(() -> {
            String domInvaderPath = AutoVaderExtension.domInvaderPath;
            DOMInvaderConfig.Profile profile = DOMInvaderConfig.customProfile(projectCanary);
            profile.setRedirectBreakpoint(true);
            int delay = settings.getInteger("Delay MS");
            new PlaywrightRenderer(new DOMInvaderConfig(profile), deduper, true)
                    .renderUrls(Collections.singletonList(url), domInvaderPath, false, false, false, delay);
        });
    }

    // Helper methods for extracting data from context events
    public static List<String> extractUrlsFromEvent(ContextMenuEvent event) {
        if (!event.selectedRequestResponses().isEmpty()) {
            return event.selectedRequestResponses().stream()
                    .map(requestResponse -> requestResponse.request().url())
                    .toList();
        } else if (event.messageEditorRequestResponse().isPresent()) {
            return Collections.singletonList(
                    event.messageEditorRequestResponse()
                            .get()
                            .requestResponse()
                            .request()
                            .url());
        }
        return null;
    }

    public static List<HttpRequestResponse> extractRequestResponsesFromEvent(ContextMenuEvent event) {
        if (!event.selectedRequestResponses().isEmpty()) {
            return event.selectedRequestResponses();
        } else if (event.messageEditorRequestResponse().isPresent()) {
            return Collections.singletonList(
                    event.messageEditorRequestResponse()
                            .get()
                            .requestResponse());
        }
        return null;
    }

    public static String extractSingleUrlFromEvent(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isPresent()) {
            return event.messageEditorRequestResponse()
                    .get()
                    .requestResponse()
                    .request()
                    .url();
        }
        return null;
    }

    // Helper methods for extracting data from message editor (for hotkeys)
    public static String extractUrlFromMessageEditor(MessageEditorHttpRequestResponse messageEditor) {
        if (messageEditor != null) {
            return messageEditor.requestResponse().request().url();
        }
        return null;
    }

    public static List<String> extractUrlsFromMessageEditor(MessageEditorHttpRequestResponse messageEditor) {
        if (messageEditor != null) {
            return Collections.singletonList(messageEditor.requestResponse().request().url());
        }
        return Collections.emptyList();
    }

    public static List<HttpRequestResponse> extractRequestResponsesFromMessageEditor(MessageEditorHttpRequestResponse messageEditor) {
        if (messageEditor != null) {
            return Collections.singletonList(messageEditor.requestResponse());
        }
        return Collections.emptyList();
    }

    // Private helper methods
    private void executeScan(List<String> urls, ScanProcessor scanProcessor, ScanType scanType) {
        AutoVaderExtension.executorService.submit(() -> {
            String domInvaderPath = AutoVaderExtension.domInvaderPath;
            String canary = projectCanary;
            int delay = settings.getInteger("Delay MS");

            if (urls == null || urls.isEmpty()) {
                api.logging().logToOutput("No URLs to scan");
                return;
            }
            boolean someUrlsNotInScope = false;
            if(urls.stream().anyMatch(url -> !api.scope().isInScope(url))) {
                api.logging().logToOutput("URL is not in scope. Skipping all URLs that are not in scope.");
                someUrlsNotInScope = true;
            }

            List<String> urlsToScan = scanProcessor.processUrls(urls.stream().filter(url -> api.scope().isInScope(url)).toList(), canary);
            if (urlsToScan.isEmpty()) {
                api.logging().logToOutput("No URLs to scan after processing");
                if(someUrlsNotInScope) {
                    alert("You need to add the URLs you want to scan to the scope");
                }
                return;
            }

            api.logging().logToOutput("Scanning " + urlsToScan.size() + " URLs with canary: " + canary);
            DOMInvaderConfig.Profile profile = createScanProfile(canary, scanType);
            new PlaywrightRenderer(new DOMInvaderConfig(profile), deduper, false)
                    .renderUrls(urlsToScan, domInvaderPath, true, false, true, delay);
            api.logging().logToOutput("Completed scanning " + urlsToScan.size() + " URLs via AutoVader");
        });
    }

    private void executeScanForPosts(List<HttpRequestResponse> requestResponses, PostScanProcessor scanProcessor, ScanType scanType) {
        AutoVaderExtension.executorService.submit(() -> {
            String domInvaderPath = AutoVaderExtension.domInvaderPath;
            String canary = projectCanary;

            if (requestResponses == null || requestResponses.isEmpty()) {
                api.logging().logToOutput("No request responses to scan");
                return;
            }

            List<HttpRequest> requestsToScan = scanProcessor.processRequests(requestResponses, canary);

            boolean someUrlsNotInScope = false;
            if(requestsToScan.stream().anyMatch(request -> !api.scope().isInScope(request.url()))) {
                api.logging().logToOutput("URL is not in scope. Skipping all URLs that are not in scope.");
                someUrlsNotInScope = true;
            }

            if (requestsToScan.isEmpty()) {
                api.logging().logToOutput("No requests with POST parameters to scan");
                if(someUrlsNotInScope) {
                    alert("You need to add the URLs you want to scan to the scope");
                }
                return;
            }

            requestsToScan = requestsToScan.stream().filter(request -> api.scope().isInScope(request.url())).collect(Collectors.toList());

            api.logging().logToOutput("Scanning " + requestsToScan.size() + " requests with canary: " + canary);
            DOMInvaderConfig.Profile profile = createScanProfile(canary, scanType);
            int delay = settings.getInteger("Delay MS");
            new PlaywrightRenderer(new DOMInvaderConfig(profile), deduper, false)
                    .renderHttpRequests(requestsToScan, domInvaderPath, true, false, true, delay);
            api.logging().logToOutput("Completed scanning " + requestsToScan.size() + " requests via AutoVader");
        });
    }

    private DOMInvaderConfig.Profile createScanProfile(String canary, ScanType scanType) {
        if (scanType == ScanType.WEB_MESSAGE) {
            return DOMInvaderConfig.customProfile(canary)
                    .setEnabled(true)
                    .setPostmessage(true)
                    .setSpoofOrigin(true)
                    .setInjectCanary(true)
                    .setDuplicateValues(true)
                    .setGuessStrings(true)
                    .setCrossDomainLeaks(true);
        } else if(scanType == ScanType.INJECT_INTO_ALL_SOURCES) {
            return DOMInvaderConfig.customProfile(canary)
                    .setEnabled(true)
                    .setInjectIntoSources(true);
        } else if(scanType == ScanType.INJECT_INTO_ALL_SOURCES_AND_CLICK) {
            return DOMInvaderConfig.customProfile(canary)
                    .setEnabled(true)
                    .setInjectIntoSources(true)
                    .setFireEvents(true);
        } else if(scanType == ScanType.CLIENT_SIDE_PROTOTYPE_POLLUTION) {
            return DOMInvaderConfig.customProfile(canary)
                    .setEnabled(true)
                    .setPrototypePollution(true)
                    .setPrototypePollutionAutoScale(true)
                    .setPrototypePollutionNested(true)
                    .setPrototypePollutionQueryString(true)
                    .setPrototypePollutionHash(true)
                    .setPrototypePollutionJson(true)
                    .setPrototypePollutionVerify(true)
                    .setPrototypePollutionCSP(false)
                    .setPrototypePollutionXFrameOptions(false)
                    .setPrototypePollutionSeparateFrame(false);
        } else if(scanType == ScanType.CLIENT_SIDE_PROTOTYPE_POLLUTION_GADGETS) {
            return DOMInvaderConfig.customProfile(canary)
                    .setEnabled(true)
                    .setPrototypePollution(true)
                    .setPrototypePollutionDiscoverProperties(true)
                    .setPrototypePollutionAutoScale(true)
                    .setPrototypePollutionNested(true)
                    .setPrototypePollutionQueryString(false)
                    .setPrototypePollutionHash(false)
                    .setPrototypePollutionJson(false)
                    .setPrototypePollutionVerify(false)
                    .setPrototypePollutionCSP(true)
                    .setPrototypePollutionXFrameOptions(true)
                    .setPrototypePollutionSeparateFrame(false);
        } else {
            return DOMInvaderConfig.customProfile(canary);
        }
    }
}