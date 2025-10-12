package burp.auto.vader.ui;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.auto.vader.*;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static burp.auto.vader.AutoVaderExtension.*;

public class AutoVaderContextMenu implements ContextMenuItemsProvider {
    private IssueDeduplicator deduper;
    private enum ScanType {
        WEB_MESSAGE,
        QUERY_PARAMS,
        CLIENT_SIDE_PROTOTYPE_POLLUTION,
        CLIENT_SIDE_PROTOTYPE_POLLUTION_GADGETS
    }

    public AutoVaderContextMenu(IssueDeduplicator deduper) {
        this.deduper = deduper;
    }

    private List<String> extractUrlsFromEvent(ContextMenuEvent event) {
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

    private void executeScan(ContextMenuEvent event, ScanProcessor scanProcessor, ScanType scanType) {
        AutoVaderExtension.executorService.submit(() -> {
            String domInvaderPath = settings.getString("DOM Invader path");
            String canary = projectCanary;
            List<String> urls = extractUrlsFromEvent(event);

            if (urls == null) {
                return;
            }

            List<String> urlsToScan = scanProcessor.processUrls(urls, canary);
            if (urlsToScan.isEmpty()) {
                api.logging().logToOutput("No URLs to scan");
                return;
            }

            api.logging().logToOutput("Scanning " + urlsToScan.size() + " URLs with canary: " + canary);
            DOMInvaderConfig.Profile profile = createScanProfile(canary, scanType);
            new PlaywrightRenderer(new DOMInvaderConfig(profile), deduper)
                    .renderUrls(urlsToScan, domInvaderPath, true, false, true);
            api.logging().logToOutput("Completed scanning " + urlsToScan.size() + " URLs via AutoVader");
        });
    }

    private interface ScanProcessor {
        List<String> processUrls(List<String> urls, String canary);
    }

    public List<Component> provideMenuItems(ContextMenuEvent event) {
        String payload = settings.getString("payload");
        List<Component> menuItemList = new ArrayList<>();
        JMenu menu = new JMenu(extensionName);
        JMenuItem openDomInvaderMenu = new JMenuItem("Open DOM Invader");
        openDomInvaderMenu.setEnabled(event.messageEditorRequestResponse().isPresent());
        openDomInvaderMenu.addActionListener(e -> {
            executorService.submit(() -> {
                String domInvaderPath = settings.getString("DOM Invader path");
                new PlaywrightRenderer(new DOMInvaderConfig(DOMInvaderConfig.customProfile(projectCanary)), deduper)
                        .renderUrls(Collections.singletonList(event.messageEditorRequestResponse().get().requestResponse().request().url()), domInvaderPath, false, false, false);
            });
        });
        menu.add(openDomInvaderMenu);
        JMenuItem scanAllQueryParametersMenu = new JMenuItem("Scan all query params");
        scanAllQueryParametersMenu.addActionListener(e ->
            executeScan(event, (urls, canary) -> {
                List<String> enumeratedUrls = Utils.enumerateQueryParameters(urls, canary, payload);
                api.logging().logToOutput("Urls:" + enumeratedUrls);
                if (enumeratedUrls.isEmpty()) {
                    api.logging().logToOutput("No query parameters found to scan");
                }
                return enumeratedUrls;
            }, ScanType.QUERY_PARAMS)
        );
        menu.add(scanAllQueryParametersMenu);
        JMenuItem scanWebMessagesMenu = new JMenuItem("Scan web messages");
        scanWebMessagesMenu.addActionListener(e ->
            executeScan(event, (urls, canary) -> urls, ScanType.WEB_MESSAGE)
        );
        menu.add(scanWebMessagesMenu);
        JMenuItem prototypePollutionMenu = new JMenuItem("Scan for client side prototype pollution");
        prototypePollutionMenu.addActionListener(e ->
                executeScan(event, (urls, canary) -> urls, ScanType.CLIENT_SIDE_PROTOTYPE_POLLUTION)
        );
        menu.add(prototypePollutionMenu);
        JMenuItem prototypePollutionGadgetsMenu = new JMenuItem("Scan for client side prototype pollution gadgets");
        prototypePollutionGadgetsMenu.addActionListener(e ->
                executeScan(event, (urls, canary) -> urls, ScanType.CLIENT_SIDE_PROTOTYPE_POLLUTION_GADGETS)
        );
        menu.add(prototypePollutionGadgetsMenu);
        menuItemList.add(menu);

        return menuItemList;
    }
}
