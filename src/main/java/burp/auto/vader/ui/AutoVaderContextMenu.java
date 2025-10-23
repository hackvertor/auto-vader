package burp.auto.vader.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.auto.vader.*;
import burp.auto.vader.actions.AutoVaderActions;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static burp.auto.vader.AutoVaderExtension.*;

public class AutoVaderContextMenu implements ContextMenuItemsProvider {
    private final AutoVaderActions actions;

    public AutoVaderContextMenu(IssueDeduplicator deduper) {
        this.actions = new AutoVaderActions(deduper);
    }


    static void sortMenu(JMenu menu) {
        List<JMenuItem> items = new ArrayList<>();
        for (int i = 0; i < menu.getItemCount(); i++) {
            JMenuItem item = menu.getItem(i);
            if (item != null) items.add(item);
        }
        items.sort(Comparator.comparing(JMenuItem::getText, String.CASE_INSENSITIVE_ORDER));
        menu.removeAll();
        for (JMenuItem item : items) menu.add(item);
    }

    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItemList = new ArrayList<>();
        JMenu menu = new JMenu(extensionName);

        // Open DOM Invader
        JMenuItem openDomInvaderMenu = new JMenuItem("Open DOM Invader");
        openDomInvaderMenu.setEnabled(event.messageEditorRequestResponse().isPresent());
        openDomInvaderMenu.addActionListener(e -> {
            String url = AutoVaderActions.extractSingleUrlFromEvent(event);
            if (url != null) {
                actions.openDOMInvader(url);
            }
        });
        menu.add(openDomInvaderMenu);

        // Scan all GET params
        JMenuItem scanAllQueryParametersMenu = new JMenuItem("Scan all GET params");
        scanAllQueryParametersMenu.addActionListener(e -> {
            List<String> urls = AutoVaderActions.extractUrlsFromEvent(event);
            if (urls != null) {
                actions.scanAllQueryParameters(urls);
            }
        });
        menu.add(scanAllQueryParametersMenu);

        // Scan all POST params
        JMenuItem scanAllPostParametersMenu = new JMenuItem("Scan all POST params");
        scanAllPostParametersMenu.addActionListener(e -> {
            List<HttpRequestResponse> requestResponses = AutoVaderActions.extractRequestResponsesFromEvent(event);
            if (requestResponses != null) {
                actions.scanAllPostParameters(requestResponses);
            }
        });
        menu.add(scanAllPostParametersMenu);

        // Scan web messages
        JMenuItem scanWebMessagesMenu = new JMenuItem("Scan web messages");
        scanWebMessagesMenu.addActionListener(e -> {
            List<String> urls = AutoVaderActions.extractUrlsFromEvent(event);
            if (urls != null) {
                actions.scanWebMessages(urls);
            }
        });
        menu.add(scanWebMessagesMenu);

        // Inject into all sources
        JMenuItem injectIntoAllSourcesMenu = new JMenuItem("Inject into all sources");
        injectIntoAllSourcesMenu.addActionListener(e -> {
            List<String> urls = AutoVaderActions.extractUrlsFromEvent(event);
            if (urls != null) {
                actions.injectIntoAllSources(urls);
            }
        });
        menu.add(injectIntoAllSourcesMenu);

        // Inject into all sources & click everything
        JMenuItem injectIntoAllSourcesAndClickMenu = new JMenuItem("Inject into all sources & click everything");
        injectIntoAllSourcesAndClickMenu.addActionListener(e -> {
            List<String> urls = AutoVaderActions.extractUrlsFromEvent(event);
            if (urls != null) {
                actions.injectIntoAllSourcesAndClick(urls);
            }
        });
        menu.add(injectIntoAllSourcesAndClickMenu);

        // Scan for client side prototype pollution
        JMenuItem prototypePollutionMenu = new JMenuItem("Scan for client side prototype pollution");
        prototypePollutionMenu.addActionListener(e -> {
            List<String> urls = AutoVaderActions.extractUrlsFromEvent(event);
            if (urls != null) {
                actions.scanPrototypePollution(urls);
            }
        });
        menu.add(prototypePollutionMenu);

        // Scan for client side prototype pollution gadgets
        JMenuItem prototypePollutionGadgetsMenu = new JMenuItem("Scan for client side prototype pollution gadgets");
        prototypePollutionGadgetsMenu.addActionListener(e -> {
            List<String> urls = AutoVaderActions.extractUrlsFromEvent(event);
            if (urls != null) {
                actions.scanPrototypePollutionGadgets(urls);
            }
        });
        menu.add(prototypePollutionGadgetsMenu);

        // Intercept client side redirect
        JMenuItem redirectBreakpointMenu = new JMenuItem("Intercept client side redirect");
        redirectBreakpointMenu.setEnabled(event.messageEditorRequestResponse().isPresent());
        redirectBreakpointMenu.addActionListener(e -> {
            String url = AutoVaderActions.extractSingleUrlFromEvent(event);
            if (url != null) {
                actions.interceptClientSideRedirect(url);
            }
        });
        menu.add(redirectBreakpointMenu);

        sortMenu(menu);
        menuItemList.add(menu);
        return menuItemList;
    }
}
