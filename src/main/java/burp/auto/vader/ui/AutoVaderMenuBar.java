package burp.auto.vader.ui;

import burp.auto.vader.Utils;

import javax.swing.*;

import static burp.auto.vader.AutoVaderExtension.extensionName;
import static burp.auto.vader.AutoVaderExtension.sharedConfig;

public class AutoVaderMenuBar {
    public static JMenu generateMenuBar() {
        JMenu menu = new JMenu(extensionName);
        JMenuItem customiseCallbacksMenu = new JMenuItem("Customise callbacks");
        customiseCallbacksMenu.addActionListener(e ->
            SwingUtilities.invokeLater(() -> new CustomiseCallbacksFrame(sharedConfig))
        );
        menu.add(customiseCallbacksMenu);
        JMenuItem reportFeedbackMenu = new JMenuItem("Report feedback");
        reportFeedbackMenu.addActionListener(e -> {
            Utils.openUrl("https://github.com/hackvertor/auto-vader/issues/new");
        });
        menu.add(reportFeedbackMenu);
        return menu;
    }
}
