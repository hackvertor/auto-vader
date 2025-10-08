package burp.auto.vader.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.auto.vader.AutoVaderExtension;
import burp.auto.vader.DOMInvaderDataStore;
import burp.auto.vader.model.MessageDetails;
import burp.auto.vader.model.SinkDetails;
import burp.auto.vader.model.SourceDetails;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;

public class AutoVaderTab implements ExtensionProvidedHttpRequestEditor {

    private HttpRequest currentRequest;
    private JTabbedPane tabbedPane;
    private JTextArea sinksTextArea;
    private JTextArea sourcesTextArea;
    private JTextArea messagesTextArea;
    private JTable sinksTable;
    private JTable sourcesTable;
    private JTable messagesTable;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public AutoVaderTab() {
        initializeUI();
    }

    private void initializeUI() {
        tabbedPane = new JTabbedPane();

        // Sinks tab
        JSplitPane sinksPanel = createDataPanel();
        sinksTable = (JTable) ((JScrollPane) sinksPanel.getLeftComponent()).getViewport().getView();
        sinksTextArea = (JTextArea) ((JScrollPane) sinksPanel.getRightComponent()).getViewport().getView();
        String[] sinkColumns = {"Type", "Sink", "Value", "Interesting"};
        ((DefaultTableModel) sinksTable.getModel()).setColumnIdentifiers(sinkColumns);
        tabbedPane.addTab("Sinks", sinksPanel);

        // Sources tab
        JSplitPane sourcesPanel = createDataPanel();
        sourcesTable = (JTable) ((JScrollPane) sourcesPanel.getLeftComponent()).getViewport().getView();
        sourcesTextArea = (JTextArea) ((JScrollPane) sourcesPanel.getRightComponent()).getViewport().getView();
        String[] sourceColumns = {"Type", "Source", "Value", "Interesting"};
        ((DefaultTableModel) sourcesTable.getModel()).setColumnIdentifiers(sourceColumns);
        tabbedPane.addTab("Sources", sourcesPanel);

        // Messages tab
        JSplitPane messagesPanel = createDataPanel();
        messagesTable = (JTable) ((JScrollPane) messagesPanel.getLeftComponent()).getViewport().getView();
        messagesTextArea = (JTextArea) ((JScrollPane) messagesPanel.getRightComponent()).getViewport().getView();
        String[] messageColumns = {"Type", "Title", "Severity", "Confidence"};
        ((DefaultTableModel) messagesTable.getModel()).setColumnIdentifiers(messageColumns);
        tabbedPane.addTab("Messages", messagesPanel);
    }

    private JSplitPane createDataPanel() {
        // Left: Table
        DefaultTableModel tableModel = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        JScrollPane tableScrollPane = new JScrollPane(table);

        // Right: Detail view
        JTextArea detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(false);
        detailArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane detailScrollPane = new JScrollPane(detailArea);

        // Split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableScrollPane, detailScrollPane);
        splitPane.setDividerLocation(400);
        splitPane.setResizeWeight(0.5);

        // Add selection listener
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow >= 0) {
                    Object rowData = table.getModel().getValueAt(selectedRow, table.getColumnCount() - 1);
                    if (rowData != null) {
                        detailArea.setText(rowData.toString());
                        detailArea.setCaretPosition(0);
                    }
                }
            }
        });

        return splitPane;
    }

    @Override
    public HttpRequest getRequest() {
        return currentRequest;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        if (requestResponse == null) {
            return;
        }

        this.currentRequest = requestResponse.request();
        String url = currentRequest.url();

        // Extract origin and load data
        DOMInvaderDataStore dataStore = AutoVaderExtension.dataStore;
        String origin = dataStore.extractOrigin(url);
        DOMInvaderDataStore.OriginData data = dataStore.getDataForOrigin(origin);

        // Update UI on EDT
        SwingUtilities.invokeLater(() -> updateUI(data));
    }

    private void updateUI(DOMInvaderDataStore.OriginData data) {
        // Clear existing data
        ((DefaultTableModel) sinksTable.getModel()).setRowCount(0);
        ((DefaultTableModel) sourcesTable.getModel()).setRowCount(0);
        ((DefaultTableModel) messagesTable.getModel()).setRowCount(0);
        sinksTextArea.setText("");
        sourcesTextArea.setText("");
        messagesTextArea.setText("");

        if (data == null) {
            return;
        }

        // Populate sinks
        List<SinkDetails> sinks = data.getSinks();
        DefaultTableModel sinkModel = (DefaultTableModel) sinksTable.getModel();
        for (SinkDetails sink : sinks) {
            String json = gson.toJson(sink);
            sinkModel.addRow(new Object[]{
                "Sink",
                sink.getSink() != null ? sink.getSink() : "",
                sink.getValue() != null ? truncate(sink.getValue(), 50) : "",
                sink.isInteresting() ? "Yes" : "No",
                json
            });
        }

        // Populate sources
        List<SourceDetails> sources = data.getSources();
        DefaultTableModel sourceModel = (DefaultTableModel) sourcesTable.getModel();
        for (SourceDetails source : sources) {
            String json = gson.toJson(source);
            sourceModel.addRow(new Object[]{
                "Source",
                source.getSource() != null ? source.getSource() : "",
                source.getValue() != null ? truncate(source.getValue(), 50) : "",
                source.isInteresting() ? "Yes" : "No",
                json
            });
        }

        // Populate messages
        List<MessageDetails> messages = data.getMessages();
        DefaultTableModel messageModel = (DefaultTableModel) messagesTable.getModel();
        for (MessageDetails msg : messages) {
            String json = gson.toJson(msg);
            messageModel.addRow(new Object[]{
                msg.getMessageType() != null ? msg.getMessageType() : "Message",
                msg.getTitle() != null ? msg.getTitle() : "",
                msg.getSeverity() != null ? msg.getSeverity() : "",
                msg.getConfidence() != null ? msg.getConfidence() : "",
                json
            });
        }
    }

    private String truncate(String str, int maxLength) {
        if (str == null || str.length() <= maxLength) {
            return str;
        }
        return str.substring(0, maxLength) + "...";
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.request() == null) {
            return false;
        }

        String url = requestResponse.request().url();
        String origin = AutoVaderExtension.dataStore.extractOrigin(url);
        DOMInvaderDataStore.OriginData data = AutoVaderExtension.dataStore.getDataForOrigin(origin);

        return data != null && data.getTotalCount() > 0;
    }

    @Override
    public String caption() {
        return "AutoVader";
    }

    @Override
    public Component uiComponent() {
        return tabbedPane;
    }

    @Override
    public Selection selectedData() {
        return null;
    }

    @Override
    public boolean isModified() {
        return false;
    }
}
