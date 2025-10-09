package burp.auto.vader.ui;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.auto.vader.AutoVaderExtension;
import burp.auto.vader.DOMInvaderConfig;
import burp.auto.vader.PlaywrightRenderer;
import burp.auto.vader.Utils;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static burp.auto.vader.AutoVaderExtension.*;

public class AutoVaderContextMenu implements ContextMenuItemsProvider {

    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItemList = new ArrayList<>();
        JMenu menu = new JMenu("Auto Vader");
        JMenuItem scanAllQueryParametersMenu = new JMenuItem("Scan all query params");
        scanAllQueryParametersMenu.addActionListener(
                e -> {
                    AutoVaderExtension.executorService.submit(
                            () -> {
                                String domInvaderPath = settings.getString("DOM Invader path");
                                String canary = Utils.generateCanary();
                                List<String> urls = null;

                                if (!event.selectedRequestResponses().isEmpty()) {
                                    urls =
                                            event.selectedRequestResponses().stream()
                                                    .map(requestResponse -> requestResponse.request().url())
                                                    .toList();
                                } else {
                                    if (event.messageEditorRequestResponse().isPresent()) {
                                        urls =
                                                Collections.singletonList(
                                                        event
                                                                .messageEditorRequestResponse()
                                                                .get()
                                                                .requestResponse()
                                                                .request()
                                                                .url());
                                    } else {
                                        return;
                                    }
                                }

                                // Enumerate query parameters and inject canary into each one
                                List<String> enumeratedUrls = Utils.enumerateQueryParameters(urls, canary);
                                api.logging().logToOutput("Urls:" + enumeratedUrls);
                                if (enumeratedUrls.isEmpty()) {
                                    api.logging().logToOutput("No query parameters found to scan");
                                    return;
                                }

                                api.logging().logToOutput("Scanning " + enumeratedUrls.size() + " parameter variations with canary: " + canary);
                                DOMInvaderConfig.Profile profile = DOMInvaderConfig.customProfile(canary)
                                                                        .setEnabled(true)
                                                                        .setPostmessage(true)
                                                                        .setSpoofOrigin(true)
                                                                        .setInjectCanary(true)
                                                                        .setDuplicateValues(true)
                                                                        .setGuessStrings(true)
                                                                        .setCrossDomainLeaks(true);
                                new PlaywrightRenderer(new DOMInvaderConfig(profile))
                                        .renderUrls(enumeratedUrls, domInvaderPath, true, false);
                                api.logging().logToOutput("Completed scanning " + enumeratedUrls.size() + " URLs via AutoVader");
                            });
                });
        menu.add(scanAllQueryParametersMenu);
        menuItemList.add(menu);
        return menuItemList;
    }
}
