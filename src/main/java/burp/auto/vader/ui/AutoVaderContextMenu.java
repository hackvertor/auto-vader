package burp.auto.vader.ui;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.auto.vader.PlaywrightRenderer;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import static burp.auto.vader.AutoVaderExtension.api;
import static burp.auto.vader.AutoVaderExtension.domInvaderPath;

public class AutoVaderContextMenu implements ContextMenuItemsProvider {
    private final PlaywrightRenderer playwrightRenderer;
    public AutoVaderContextMenu() {
        this.playwrightRenderer = new PlaywrightRenderer();
    }

    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItemList = new ArrayList<>();
        JMenu menu = new JMenu("Auto Vader");
        JMenuItem scanSelectedItemsMenu = new JMenuItem("Scan");
        scanSelectedItemsMenu.setEnabled(!event.selectedRequestResponses().isEmpty());
        scanSelectedItemsMenu.addActionListener(e -> {
            List<String> urls = event.selectedRequestResponses().stream()
                    .map(requestResponse -> requestResponse.request().url())
                    .toList();

            playwrightRenderer.renderUrls(urls, domInvaderPath);
            api.logging().logToOutput("Rendered " + urls.size() + " URLs via Playwright");
        });
        menu.add(scanSelectedItemsMenu);
        menuItemList.add(menu);
        return menuItemList;
    }
}
