package burp.auto.vader;

import java.util.HashMap;
import java.util.Map;

import static burp.auto.vader.AutoVaderExtension.api;

public class DOMInvaderConfig {

    private final String sinkCallback = """
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
    if(payload.isInteresting && payload.value.includes(payload.canary)) {
        sendToBurp(payload,"sink");
        return true;
    }
    return false;
}""";

    private final String sourceCallback = """
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
    if(payload.isInteresting) {
        sendToBurp(payload, "source");
        return true;
    }
    return false;
}""";

    private final String messageCallback = """
function(msg) {
    const payload = {
        isInteresting: msg.isInteresting,
        canary: msg.canary,
        id: msg.id,
        title: msg.title,
        description: `Web message data is being sent via ${msg.description.originalOrigin} to origin ${msg.description.origin} from a postMessage request. ${msg.description.extra} This event listener ${msg.description.originCheckedFirst} check the origin before accessing data.`,
        url: msg.url,
        charactersEncoded: `${msg.charactersEncoded.sinkInjection}`,
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
    
    if(payload.isInteresting) {
        sendToBurp(payload, "message");
        return true;
    }
    return false;
}""";

    public static class Profile {
        private String canary = "burpdomxss";
        private boolean enabled = true;
        private boolean crossDomainLeaks = false;
        private String[] disabledSinks = new String[0];
        private boolean domClobbering = false;
        private boolean duplicateValues = false;
        private boolean filterStack = false;
        private boolean fireEvents = false;
        private boolean guessStrings = false;
        private boolean injectCanary = false;
        private boolean injectIntoSources = false;
        private boolean permissionsPolicy = false;
        private boolean postmessage = false;
        private boolean preventRedirection = false;
        private boolean prototypePollution = false;
        private boolean prototypePollutionAutoScale = true;
        private boolean prototypePollutionCSP = false;
        private boolean prototypePollutionDiscoverProperties = false;
        private boolean prototypePollutionHash = true;
        private boolean prototypePollutionJson = true;
        private boolean prototypePollutionNested = true;
        private boolean prototypePollutionQueryString = true;
        private boolean prototypePollutionSeparateFrame = false;
        private boolean prototypePollutionVerify = true;
        private boolean prototypePollutionXFrameOptions = false;
        private boolean redirectBreakpoint = false;
        private boolean spoofOrigin = false;

        public Profile() {}

        public Profile setCanary(String canary) {
            this.canary = canary;
            return this;
        }

        public Profile setEnabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public Profile setCrossDomainLeaks(boolean crossDomainLeaks) {
            this.crossDomainLeaks = crossDomainLeaks;
            return this;
        }

        public Profile setDomClobbering(boolean domClobbering) {
            this.domClobbering = domClobbering;
            return this;
        }

        public Profile setPostmessage(boolean postmessage) {
            this.postmessage = postmessage;
            return this;
        }

        public Profile setPrototypePollution(boolean prototypePollution) {
            this.prototypePollution = prototypePollution;
            return this;
        }

        public Profile setInjectCanary(boolean injectCanary) {
            this.injectCanary = injectCanary;
            return this;
        }

        public Profile setFireEvents(boolean fireEvents) {
            this.fireEvents = fireEvents;
            return this;
        }

        public Profile setSpoofOrigin(boolean spoofOrigin) {
            this.spoofOrigin = spoofOrigin;
            return this;
        }

        public Profile setDuplicateValues(boolean duplicateValues) {
            this.duplicateValues = duplicateValues;
            return this;
        }

        public Profile setGuessStrings(boolean guessStrings) {
            this.guessStrings = guessStrings;
            return this;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> settings = new HashMap<>();
            settings.put("canary", canary);
            settings.put("enabled", enabled);
            settings.put("crossDomainLeaks", crossDomainLeaks);
            settings.put("disabledSinks", disabledSinks);
            settings.put("domClobbering", domClobbering);
            settings.put("duplicateValues", duplicateValues);
            settings.put("filterStack", filterStack);
            settings.put("fireEvents", fireEvents);
            settings.put("guessStrings", guessStrings);
            settings.put("injectCanary", injectCanary);
            settings.put("injectIntoSources", injectIntoSources);
            settings.put("permissionsPolicy", permissionsPolicy);
            settings.put("postmessage", postmessage);
            settings.put("preventRedirection", preventRedirection);
            settings.put("prototypePollution", prototypePollution);
            settings.put("prototypePollutionAutoScale", prototypePollutionAutoScale);
            settings.put("prototypePollutionCSP", prototypePollutionCSP);
            settings.put("prototypePollutionDiscoverProperties", prototypePollutionDiscoverProperties);
            settings.put("prototypePollutionHash", prototypePollutionHash);
            settings.put("prototypePollutionJson", prototypePollutionJson);
            settings.put("prototypePollutionNested", prototypePollutionNested);
            settings.put("prototypePollutionQueryString", prototypePollutionQueryString);
            settings.put("prototypePollutionSeparateFrame", prototypePollutionSeparateFrame);
            settings.put("prototypePollutionVerify", prototypePollutionVerify);
            settings.put("prototypePollutionXFrameOptions", prototypePollutionXFrameOptions);
            settings.put("redirectBreakpoint", redirectBreakpoint);
            settings.put("spoofOrigin", spoofOrigin);
            return settings;
        }
    }

    private final Profile profile;

    public DOMInvaderConfig(Profile profile) {
        this.profile = profile;
    }

    public DOMInvaderConfig() {
        this(new Profile());
    }

    public String getSinkCallback() {
        return sinkCallback;
    }

    public String getSourceCallback() {
        return sourceCallback;
    }

    public String getMessageCallback() {
        return messageCallback;
    }

    public String generateSettingsScript() {
        Map<String, Object> settings = profile.toMap();

        // Build the settings object as a JavaScript object literal
        StringBuilder settingsJson = new StringBuilder("{\n");
        boolean first = true;
        for (Map.Entry<String, Object> entry : settings.entrySet()) {
            if (!first) settingsJson.append(",\n");
            first = false;

            settingsJson.append("                ");
            settingsJson.append(entry.getKey()).append(": ");

            Object value = entry.getValue();
            if (value instanceof String) {
                settingsJson.append("'").append(value).append("'");
            } else if (value instanceof String[]) {
                settingsJson.append("[]");
            } else {
                settingsJson.append(value);
            }
        }

        // Add callbacks
        settingsJson.append(",\nsinkCallback: \"").append(escapeJavaScript(sinkCallback)).append("\"");
        settingsJson.append(",\nsourceCallback: \"").append(escapeJavaScript(sourceCallback)).append("\"");
        settingsJson.append(",\nmessageCallback: \"").append(escapeJavaScript(messageCallback)).append("\"");
        settingsJson.append("\n}");

        return """
            () => {
                chrome.storage.local.set(%s, () => {
                    console.log('DOM Invader settings saved');
                });
            }
        """.formatted(settingsJson.toString());
    }

    private String escapeJavaScript(String input) {
        return input
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }

    public static Profile defaultProfile() {
        return new Profile();
    }

    public static Profile customProfile(String canary) {
        return new Profile().setCanary(canary);
    }
}
