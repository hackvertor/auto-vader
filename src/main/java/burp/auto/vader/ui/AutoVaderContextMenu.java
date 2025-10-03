package burp.auto.vader.ui;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.auto.vader.AutoVaderExtension;
import burp.auto.vader.DOMInvaderConfig;
import burp.auto.vader.PlaywrightRenderer;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Clipboard;
import java.util.ArrayList;
import java.util.List;

import static burp.auto.vader.AutoVaderExtension.*;

public class AutoVaderContextMenu implements ContextMenuItemsProvider {

    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItemList = new ArrayList<>();
        JMenu menu = new JMenu("Auto Vader");
        JMenuItem getAllSinksMenu = new JMenuItem("Get all sinks");
        getAllSinksMenu.setEnabled(!event.selectedRequestResponses().isEmpty());
        getAllSinksMenu.addActionListener(e -> {
            AutoVaderExtension.executorService.submit(() -> {
                String domInvaderPath = settings.getString("DOM Invader path");
                List<String> urls = event.selectedRequestResponses().stream()
                        .map(requestResponse -> requestResponse.request().url())
                        .toList();
                new PlaywrightRenderer(new DOMInvaderConfig(DOMInvaderConfig.customProfile(""))).renderUrls(urls, domInvaderPath, true, false);
                api.logging().logToOutput("Rendered " + urls.size() + " URLs via Playwright");
            });
        });
        menu.add(getAllSinksMenu);
        menuItemList.add(menu);
        return menuItemList;
    }
}
