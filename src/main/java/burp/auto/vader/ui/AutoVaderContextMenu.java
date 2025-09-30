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
        JMenuItem setup = new JMenuItem("Setup");
        setup.addActionListener(e -> showSetupWindow());
        menu.add(setup);
        menuItemList.add(menu);
        return menuItemList;
    }

    private void showSetupWindow() {
        JFrame window = new JFrame("Auto Vader Setup");
        window.setSize(1024, 768);
        window.setLocationRelativeTo(null);
        window.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        JPanel containerPanel = new JPanel(new BorderLayout());

        JPanel mainPanel = new JPanel(new GridLayout(1, 2, 20, 0));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // Left column
        JPanel leftColumn = new JPanel();
        leftColumn.setLayout(new BoxLayout(leftColumn, BoxLayout.Y_AXIS));

        // Step 1: Copy token from DOM Invader canary
        JLabel step1Label = new JLabel("Step 1");
        step1Label.setAlignmentX(Component.LEFT_ALIGNMENT);
        leftColumn.add(step1Label);
        leftColumn.add(Box.createRigidArea(new Dimension(0, 5)));

        JButton launchButton = new JButton("Launch Browser");
        launchButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        launchButton.addActionListener(e -> {
            AutoVaderExtension.executorService.submit(() -> {
                String domInvaderPath = settings.getString("DOM Invader path");
                List<String> urls = List.of("https://portswigger-labs.net");

                playwrightRenderer.renderUrls(urls, domInvaderPath, false, false);
                api.logging().logToOutput("Opened setup URL - browser will remain open");
            });
        });

        JTextArea tokenArea = generateWrapTextArea("First click the Launch Browser button. Click the plug icon in the top right and click the pin. Enable DOM Invader. Click the copy button.");
        tokenArea.setAlignmentX(Component.LEFT_ALIGNMENT);
        leftColumn.add(tokenArea);
        leftColumn.add(Box.createRigidArea(new Dimension(0, 5)));
        leftColumn.add(launchButton);
        leftColumn.add(Box.createRigidArea(new Dimension(0, 5)));

        // Step 2: Sink callback
        JLabel step2Label = new JLabel("Step 2");
        step2Label.setAlignmentX(Component.LEFT_ALIGNMENT);
        leftColumn.add(step2Label);
        leftColumn.add(Box.createRigidArea(new Dimension(0, 5)));

        JLabel sinkLabel = new JLabel("Sink callback");
        sinkLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        leftColumn.add(sinkLabel);
        leftColumn.add(Box.createRigidArea(new Dimension(0, 5)));

        JTextArea sinkTextArea = new JTextArea(8, 40);
        sinkTextArea.setText("""
                function(sinkDetails, sinks, interestingSinks) {
                    const payload = {
                        isInteresting: sinkDetails.isInteresting,
                        canary: sinkDetails.canary,
                        sink: sinkDetails.sink,
                        stackTrace: sinkDetails.stackTrace,
                        value: sinkDetails.value,
                        url: sinkDetails.url,
                        framePath: sinkDetails.framePath,
                        event: sinkDetails.event,
                        outerHTML: sinkDetails.outerHTML
                    };
                
                    sendToBurp(payload,"sink");
                    return true; // return true to log sink
                }
                """);
        sinkTextArea.setLineWrap(true);
        sinkTextArea.setWrapStyleWord(true);
        JScrollPane sinkScrollPane = new JScrollPane(sinkTextArea);
        sinkScrollPane.setAlignmentX(Component.LEFT_ALIGNMENT);
        sinkScrollPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, 150));
        leftColumn.add(sinkScrollPane);
        leftColumn.add(Box.createRigidArea(new Dimension(0, 5)));

        JButton copySinkButton = new JButton("Copy to Clipboard");
        copySinkButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        copySinkButton.addActionListener(e -> copyToClipboard(sinkTextArea.getText()));
        leftColumn.add(copySinkButton);
        leftColumn.add(Box.createRigidArea(new Dimension(0, 15)));

        JPanel rightColumn = new JPanel();
        rightColumn.setLayout(new BoxLayout(rightColumn, BoxLayout.Y_AXIS));

        // Step 3: Source callback
        JLabel step3Label = new JLabel("Step 3");
        step3Label.setAlignmentX(Component.LEFT_ALIGNMENT);
        rightColumn.add(step3Label);
        rightColumn.add(Box.createRigidArea(new Dimension(0, 5)));

        JLabel sourceLabel = new JLabel("Source callback");
        sourceLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        rightColumn.add(sourceLabel);
        rightColumn.add(Box.createRigidArea(new Dimension(0, 5)));

        JTextArea sourceTextArea = new JTextArea(8, 40);
        sourceTextArea.setText("""
                function(sourceDetails, sources) {
                    const payload = {
                        isInteresting: sourceDetails.isInteresting,
                        canary: sourceDetails.canary,
                        source: sourceDetails.source,
                        stackTrace: sourceDetails.stackTrace,
                        value: sourceDetails.value,
                        url: sourceDetails.url,
                        framePath: sourceDetails.framePath,
                        event: sourceDetails.event
                    };
                
                    sendToBurp(payload, "source");
                    return true; // return true to log source
                }
                """);
        sourceTextArea.setLineWrap(true);
        sourceTextArea.setWrapStyleWord(true);
        JScrollPane sourceScrollPane = new JScrollPane(sourceTextArea);
        sourceScrollPane.setAlignmentX(Component.LEFT_ALIGNMENT);
        sourceScrollPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, 150));
        rightColumn.add(sourceScrollPane);
        rightColumn.add(Box.createRigidArea(new Dimension(0, 5)));

        JButton copySourceButton = new JButton("Copy to Clipboard");
        copySourceButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        copySourceButton.addActionListener(e -> copyToClipboard(sourceTextArea.getText()));
        rightColumn.add(copySourceButton);

        // Step 4: Message callback
        JLabel step4Label = new JLabel("Step 4");
        step4Label.setAlignmentX(Component.LEFT_ALIGNMENT);
        rightColumn.add(step4Label);
        rightColumn.add(Box.createRigidArea(new Dimension(0, 5)));

        JLabel messageLabel = new JLabel("Message callback");
        messageLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        rightColumn.add(messageLabel);
        rightColumn.add(Box.createRigidArea(new Dimension(0, 5)));

        JTextArea messageTextArea = new JTextArea(8, 40);
        messageTextArea.setText("""
                function(msg) {
                    const payload = {
                        isInteresting: msg.isInteresting,
                        canary: msg.canary,
                        id: msg.id,
                        title: msg.title,
                        description: msg.description,
                        url: msg.url,
                        charactersEncoded: msg.charactersEncoded,
                        confidence: msg.confidence,
                        dataAccessed: msg.dataAccessed,
                        dataStackTrace: msg.dataStackTrace,
                        eventListener: msg.eventListener,
                        eventListenerStack: msg.eventListenerStack,
                        followupVerified: msg.followupVerified,
                        manipulatedData: msg.manipulatedData,
                        messageType: msg.messageType,
                        origin: msg.origin,
                        originChecked: msg.originChecked,
                        originCheckedFirst: msg.originCheckedFirst,
                        originStackTrace: msg.originStackTrace,
                        originalOrigin: msg.originalOrigin,
                        postMessageData: msg.postMessageData,
                        severity: msg.severity,
                        sink: msg.sink,
                        sinkValue: msg.sinkValue,
                        sourceAccessed: msg.sourceAccessed,
                        sourceId: msg.sourceId,
                        spoofed: msg.spoofed,
                        verified: msg.verified,
                        framePathFrom: msg.framePathFrom,
                        framePathTo: msg.framePathTo
                    };
                
                    sendToBurp(payload, "message");
                    return true; // return true to log message
                }
                """);
        messageTextArea.setLineWrap(true);
        messageTextArea.setWrapStyleWord(true);
        JScrollPane messageScrollPane = new JScrollPane(messageTextArea);
        messageScrollPane.setAlignmentX(Component.LEFT_ALIGNMENT);
        messageScrollPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, 150));
        rightColumn.add(messageScrollPane);
        rightColumn.add(Box.createRigidArea(new Dimension(0, 5)));

        JButton copyMessageButton = new JButton("Copy to Clipboard");
        copyMessageButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        copyMessageButton.addActionListener(e -> copyToClipboard(messageTextArea.getText()));
        rightColumn.add(copyMessageButton);
        rightColumn.add(Box.createRigidArea(new Dimension(0, 15)));

        // Add both columns to main panel
        mainPanel.add(leftColumn);
        mainPanel.add(rightColumn);

        containerPanel.add(mainPanel, BorderLayout.CENTER);
        window.add(containerPanel);
        window.setVisible(true);
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
