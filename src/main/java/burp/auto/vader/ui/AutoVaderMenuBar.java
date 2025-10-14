package burp.auto.vader.ui;

import burp.auto.vader.Utils;

import javax.swing.*;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

import static burp.auto.vader.AutoVaderExtension.*;

public class AutoVaderMenuBar {
    public static JMenu generateMenuBar() {
        JMenu menu = new JMenu(extensionName);
        JMenuItem customiseCallbacksMenu = new JMenuItem("Customise callbacks");
        customiseCallbacksMenu.addActionListener(e ->
            SwingUtilities.invokeLater(() -> new CustomiseCallbacksFrame(sharedConfig))
        );
        menu.add(customiseCallbacksMenu);
        JMenuItem copyCanaryMenu = new JMenuItem("Copy project canary to clipboard");
        copyCanaryMenu.addActionListener(e -> {
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            StringSelection customTagCopyJSON = new StringSelection(projectCanary);
            clipboard.setContents(customTagCopyJSON, null);
        });
        menu.add(copyCanaryMenu);
        JMenuItem reportFeedbackMenu = new JMenuItem("Report feedback");
        reportFeedbackMenu.addActionListener(e -> {
            Utils.openUrl("https://github.com/hackvertor/auto-vader/issues/new");
        });
        menu.add(reportFeedbackMenu);
        return menu;
    }
}
