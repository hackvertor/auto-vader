package burp.auto.vader;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.auto.vader.model.MessageDetails;
import burp.auto.vader.model.SinkDetails;
import burp.auto.vader.model.SourceDetails;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import java.util.List;

import static burp.auto.vader.AutoVaderExtension.api;

/**
 * Reports DOM Invader findings as Burp Suite issues instead of storing them in the data store.
 */
public class DOMInvaderIssueReporter {

    private IssueDeduplicator deduper;
    private final Gson gson = new Gson();
    private final MontoyaApi montoyaApi;

    public DOMInvaderIssueReporter(MontoyaApi api, IssueDeduplicator deduper) {
        this.montoyaApi = api;
        this.deduper = deduper;
    }

    /**
     * Parses and reports a finding as a Burp Suite issue.
     *
     * @param json The JSON string containing the message data
     * @param type The type of message: "sink", "source", or "message"
     * @param url The URL from which the message originated
     * @return true if parsing and reporting succeeded, false otherwise
     */
    public boolean parseAndReport(String json, String type, String url) {
        try {
            switch (type.toLowerCase()) {
                case "sink":
                    SinkDetails sink = gson.fromJson(json, SinkDetails.class);
                    reportSinkIssue(sink, url);
                    return true;

                case "source":
                    SourceDetails source = gson.fromJson(json, SourceDetails.class);
                    reportSourceIssue(source, url);
                    return true;

                case "message":
                    MessageDetails message = gson.fromJson(json, MessageDetails.class);
                    reportMessageIssue(message, url);
                    return true;

                default:
                    api.logging().logToError("Unknown message type: " + type);
                    return false;
            }
        } catch (JsonSyntaxException e) {
            api.logging().logToError("Failed to parse JSON: " + e.getMessage());
            return false;
        } catch (Exception e) {
            api.logging().logToError("Error processing message: " + e.getMessage());
            return false;
        }
    }

    private void reportSinkIssue(SinkDetails sink, String url) {
        String issueName = "DOM XSS Sink: " + sink.getSink();
        
        StringBuilder detail = new StringBuilder();
        detail.append("<p>A DOM XSS sink was identified in the application.</p>");
        detail.append("<p><b>Sink:</b> ").append(escapeHtml(sink.getSink())).append("</p>");
        detail.append("<p><b>Value:</b> ").append(escapeHtml(sink.getValue())).append("</p>");
        detail.append("<p><b>Canary:</b> ").append(escapeHtml(sink.getCanary())).append("</p>");
        
        if (sink.getStackTrace() != null) {
            detail.append("<p><b>Stack Trace:</b><pre>").append(escapeHtml(sink.getStackTrace())).append("</pre></p>");
        }
        
        if (sink.getOuterHTML() != null) {
            detail.append("<p><b>Outer HTML:</b><pre>").append(escapeHtml(sink.getOuterHTML())).append("</pre></p>");
        }

        createIssue(issueName, detail.toString(), url, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN);
    }

    private void reportSourceIssue(SourceDetails source, String url) {
        String issueName = "DOM XSS Source: " + source.getSource();
        
        StringBuilder detail = new StringBuilder();
        detail.append("<p>A DOM XSS source was identified in the application.</p>");
        detail.append("<p><b>Source:</b> ").append(escapeHtml(source.getSource())).append("</p>");
        detail.append("<p><b>Value:</b> ").append(escapeHtml(source.getValue())).append("</p>");
        detail.append("<p><b>Canary:</b> ").append(escapeHtml(source.getCanary())).append("</p>");
        
        if (source.getStackTrace() != null) {
            detail.append("<p><b>Stack Trace:</b><pre>").append(escapeHtml(source.getStackTrace())).append("</pre></p>");
        }

        createIssue(issueName, detail.toString(), url, AuditIssueSeverity.INFORMATION, AuditIssueConfidence.CERTAIN);
    }

    private void reportMessageIssue(MessageDetails message, String url) {
        String issueName = message.getTitle() != null ? message.getTitle() : "PostMessage Vulnerability";
        
        StringBuilder detail = new StringBuilder();
        if (message.getDescription() != null) {
            detail.append("<p>").append(escapeHtml(message.getDescription())).append("</p>");
        }
        
        detail.append("<p><b>Message Type:</b> ").append(escapeHtml(message.getMessageType())).append("</p>");
        detail.append("<p><b>Origin:</b> ").append(escapeHtml(message.getOrigin())).append("</p>");
        
        if (message.getPostMessageData() != null) {
            detail.append("<p><b>PostMessage Data:</b><pre>").append(escapeHtml(message.getPostMessageData())).append("</pre></p>");
        }
        
        if (message.getSink() != null) {
            detail.append("<p><b>Sink:</b> ").append(escapeHtml(message.getSink())).append("</p>");
        }
        
        if (message.getSinkValue() != null) {
            detail.append("<p><b>Sink Value:</b> ").append(escapeHtml(message.getSinkValue())).append("</p>");
        }
        
        if (message.getConfidence() != null) {
            detail.append("<p><b>Confidence:</b> ").append(escapeHtml(message.getConfidence())).append("</p>");
        }
        
        if (message.getCanary() != null) {
            detail.append("<p><b>Canary:</b> ").append(escapeHtml(message.getCanary())).append("</p>");
        }

        // Map severity from message
        AuditIssueSeverity severity = mapSeverity(message.getSeverity());
        AuditIssueConfidence confidence = mapConfidence(message.getConfidence());

        createIssue(issueName, detail.toString(), url, severity, confidence);
    }

    private AuditIssueSeverity mapSeverity(String severity) {
        if (severity == null) {
            return AuditIssueSeverity.INFORMATION;
        }
        
        switch (severity.toLowerCase()) {
            case "high":
                return AuditIssueSeverity.HIGH;
            case "medium":
                return AuditIssueSeverity.MEDIUM;
            case "low":
                return AuditIssueSeverity.LOW;
            default:
                return AuditIssueSeverity.INFORMATION;
        }
    }

    private AuditIssueConfidence mapConfidence(String confidence) {
        if (confidence == null) {
            return AuditIssueConfidence.TENTATIVE;
        }
        
        switch (confidence.toLowerCase()) {
            case "certain":
            case "high":
                return AuditIssueConfidence.CERTAIN;
            case "firm":
            case "medium":
                return AuditIssueConfidence.FIRM;
            case "tentative":
            case "low":
                return AuditIssueConfidence.TENTATIVE;
            default:
                return AuditIssueConfidence.TENTATIVE;
        }
    }

    private void createIssue(String name, String detail, String url, AuditIssueSeverity severity, AuditIssueConfidence confidence) {
        // Create a minimal HTTP request for the issue
        HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl(url),
            null
        );

        AuditIssue issue = AuditIssue.auditIssue(
            name,
            detail,
            null, // No remediation detail
            url,
            severity,
            confidence,
            null, // No background
            null, // No remediation background
            severity,
            requestResponse
        );

        deduper.addIssueIfNew(issue);
    }

    private String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        return text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }
}