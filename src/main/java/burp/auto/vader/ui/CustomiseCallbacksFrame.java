package burp.auto.vader.ui;

import burp.auto.vader.DOMInvaderConfig;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.Map;

import static burp.auto.vader.AutoVaderExtension.api;

public class CustomiseCallbacksFrame extends JFrame {
    private final DOMInvaderConfig config;
    private JTextArea sinkCallbackTextArea;
    private JTextArea sourceCallbackTextArea;
    private JTextArea messageCallbackTextArea;
    private JComboBox<String> sinkExamplesCombo;
    private Map<String, String> sinkExamples;

    public CustomiseCallbacksFrame(DOMInvaderConfig config) {
        this.config = config;
        initializeSinkExamples();
        initializeUI();
    }

    private void initializeSinkExamples() {
        sinkExamples = new LinkedHashMap<>();

        // Add default option
        sinkExamples.put("Default", DOMInvaderConfig.DEFAULT_SINK_CALLBACK);

        // Add custom sink example
        sinkExamples.put("Alert & Interesting Sinks",
            "function(sinkDetails, sinks, interestingSinks) {\n" +
            "    const payload = {\n" +
            "        isInteresting: sinkDetails.isInteresting,\n" +
            "        canary: sinkDetails.canary,\n" +
            "        sink: sinkDetails.sink,\n" +
            "        stackTrace: sinkDetails.stackTrace,\n" +
            "        value: sinkDetails.value,\n" +
            "        url: sinkDetails.url,\n" +
            "        framePath: sinkDetails.framePath,\n" +
            "        event: sinkDetails.event,\n" +
            "        outerHTML: sinkDetails.outerHTML\n" +
            "    };\n" +
            "    \n" +
            "    //Note you have to configure a custom sink in DOM Invader\n" +
            "    if(payload.sink.includes(\"alert\") && payload.value.includes(payload.canary)) {\n" +
            "        sendToBurp(payload,\"sink\");\n" +
            "        return true;\n" +
            "    }\n" +
            "    \n" +
            "    if(payload.isInteresting && payload.value.includes(payload.canary)) {\n" +
            "        sendToBurp(payload,\"sink\");\n" +
            "        return true;\n" +
            "    }\n" +
            "    return false;\n" +
            "}");
    }

    private void initializeUI() {
        setTitle("Customise Callbacks");
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout());

        // Create main panel with padding
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(new EmptyBorder(15, 15, 15, 15));

        // Create scroll pane for the main panel
        JScrollPane mainScrollPane = new JScrollPane(mainPanel);
        mainScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        mainScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        // Add callback sections
        mainPanel.add(createSinkCallbackSection());
        mainPanel.add(Box.createVerticalStrut(20));

        mainPanel.add(createCallbackSection("Source Callback", config.getSourceCallback(),
            textArea -> sourceCallbackTextArea = textArea));
        mainPanel.add(Box.createVerticalStrut(20));

        mainPanel.add(createCallbackSection("Message Callback", config.getMessageCallback(),
            textArea -> messageCallbackTextArea = textArea));

        // Create button panel
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JButton closeButton = new JButton("Close");
        JButton updateButton = new JButton("Update Callbacks");
        JButton resetButton = new JButton("Reset to Defaults");

        // Add action listeners
        closeButton.addActionListener(e -> dispose());

        updateButton.addActionListener(e -> updateCallbacks());

        resetButton.addActionListener(e -> resetToDefaults());

        buttonPanel.add(closeButton);
        buttonPanel.add(Box.createHorizontalStrut(10));
        buttonPanel.add(resetButton);
        buttonPanel.add(Box.createHorizontalStrut(10));
        buttonPanel.add(updateButton);

        // Add components to frame
        add(mainScrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        // Set frame properties
        setSize(900, 800);
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private JPanel createSinkCallbackSection() {
        JPanel panel = new JPanel(new BorderLayout());

        // Create top panel for label and combo box
        JPanel topPanel = new JPanel(new BorderLayout());

        // Create label
        JLabel callbackLabel = new JLabel("Sink Callback");
        callbackLabel.setFont(new Font("Arial", Font.BOLD, 14));
        callbackLabel.setBorder(new EmptyBorder(0, 0, 5, 0));

        // Create combo box panel
        JPanel comboPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        JLabel exampleLabel = new JLabel("Examples:");
        sinkExamplesCombo = new JComboBox<>(sinkExamples.keySet().toArray(new String[0]));
        sinkExamplesCombo.setSelectedIndex(0);

        // Add combo box listener
        sinkExamplesCombo.addActionListener(e -> {
            String selectedKey = (String) sinkExamplesCombo.getSelectedItem();
            if (selectedKey != null && sinkExamples.containsKey(selectedKey)) {
                sinkCallbackTextArea.setText(sinkExamples.get(selectedKey));
            }
        });

        comboPanel.add(exampleLabel);
        comboPanel.add(sinkExamplesCombo);

        topPanel.add(callbackLabel, BorderLayout.NORTH);
        topPanel.add(comboPanel, BorderLayout.SOUTH);

        // Create text area
        sinkCallbackTextArea = new JTextArea(config.getSinkCallback());
        sinkCallbackTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        sinkCallbackTextArea.setTabSize(4);
        sinkCallbackTextArea.setLineWrap(false);

        // Create scroll pane for text area
        JScrollPane scrollPane = new JScrollPane(sinkCallbackTextArea);
        scrollPane.setPreferredSize(new Dimension(850, 200));
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createCallbackSection(String label, String callbackCode,
                                         java.util.function.Consumer<JTextArea> textAreaSetter) {
        JPanel panel = new JPanel(new BorderLayout());

        // Create label
        JLabel callbackLabel = new JLabel(label);
        callbackLabel.setFont(new Font("Arial", Font.BOLD, 14));
        callbackLabel.setBorder(new EmptyBorder(0, 0, 5, 0));

        // Create text area
        JTextArea textArea = new JTextArea(callbackCode);
        textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        textArea.setTabSize(4);
        textArea.setLineWrap(false);

        // Store reference to text area
        textAreaSetter.accept(textArea);

        // Create scroll pane for text area
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(850, 200));
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        panel.add(callbackLabel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private void updateCallbacks() {
        try {
            // Update the config object
            config.setSinkCallback(sinkCallbackTextArea.getText());
            config.setSourceCallback(sourceCallbackTextArea.getText());
            config.setMessageCallback(messageCallbackTextArea.getText());

            // Save to Burp's persistence API
            if (api != null && api.persistence() != null) {
                api.persistence().extensionData().setString("sinkCallback", sinkCallbackTextArea.getText());
                api.persistence().extensionData().setString("sourceCallback", sourceCallbackTextArea.getText());
                api.persistence().extensionData().setString("messageCallback", messageCallbackTextArea.getText());
            }

            JOptionPane.showMessageDialog(this,
                "Callbacks updated successfully!",
                "Success",
                JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                "Error updating callbacks: " + e.getMessage(),
                "Error",
                JOptionPane.ERROR_MESSAGE);
        }
    }

    private void resetToDefaults() {
        int result = JOptionPane.showConfirmDialog(this,
            "Are you sure you want to reset all callbacks to their default values?",
            "Reset to Defaults",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);

        if (result == JOptionPane.YES_OPTION) {
            sinkCallbackTextArea.setText(DOMInvaderConfig.DEFAULT_SINK_CALLBACK);
            sourceCallbackTextArea.setText(DOMInvaderConfig.DEFAULT_SOURCE_CALLBACK);
            messageCallbackTextArea.setText(DOMInvaderConfig.DEFAULT_MESSAGE_CALLBACK);

            JOptionPane.showMessageDialog(this,
                "Callbacks reset to defaults. Click 'Update Callbacks' to save.",
                "Reset Complete",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
}