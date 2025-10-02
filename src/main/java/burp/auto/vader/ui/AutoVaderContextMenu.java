package burp.auto.vader.ui;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.auto.vader.AutoVaderExtension;
import burp.auto.vader.PlaywrightRenderer;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Clipboard;
import java.util.ArrayList;
import java.util.List;

import static burp.auto.vader.AutoVaderExtension.*;

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
            AutoVaderExtension.executorService.submit(() -> {
                String domInvaderPath = settings.getString("DOM Invader path");
                List<String> urls = event.selectedRequestResponses().stream()
                        .map(requestResponse -> requestResponse.request().url())
                        .toList();

                playwrightRenderer.renderUrls(urls, domInvaderPath, false, false);
                api.logging().logToOutput("Rendered " + urls.size() + " URLs via Playwright");
            });
        });
        menu.add(scanSelectedItemsMenu);
        menuItemList.add(menu);
        return menuItemList;
    }

    private void copyToClipboard(String text) {
        StringSelection selection = new StringSelection(text);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(selection, selection);
    }

    private JTextArea generateWrapTextArea(String text) {
        JTextArea area = new JTextArea(text);
        area.setWrapStyleWord(true);
        area.setLineWrap(true);
        area.setEditable(false);
        area.setOpaque(false);
        area.setBorder(null);
        return area;
    }
}
