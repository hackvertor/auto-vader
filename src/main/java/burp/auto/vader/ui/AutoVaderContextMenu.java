package burp.auto.vader.ui;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import java.awt.*;
import java.util.List;

public class AutoVaderContextMenu implements ContextMenuItemsProvider {
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if(!event.selectedRequestResponses().isEmpty()) {
            
        }
    }
}
