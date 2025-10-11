package burp.auto.vader;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import java.util.HashSet;
import java.util.Set;

public class IssueDeduplicator {
    private final MontoyaApi api;
    private final Set<String> seenIssues = new HashSet<>();

    public IssueDeduplicator(MontoyaApi api) {
        this.api = api;
        for (AuditIssue existing : api.siteMap().issues()) {
            seenIssues.add(makeKey(existing));
        }
    }

    public void addIssueIfNew(AuditIssue issue) {
        String key = makeKey(issue);
        if (!seenIssues.contains(key)) {
            seenIssues.add(key);
            api.siteMap().add(issue);
            api.logging().logToOutput("Reported issue for URL: " + issue.baseUrl());
        } else {
            api.logging().logToOutput("Skipped adding duplicate issue");
        }
    }

    private String makeKey(AuditIssue issue) {
        String url = issue.baseUrl();
        String name = issue.name();
        String severity = issue.severity().name();
        return (url + "|" + name + "|" + severity).toLowerCase();
    }
}
