package burp.auto.vader;

import burp.auto.vader.model.MessageDetails;
import burp.auto.vader.model.SinkDetails;
import burp.auto.vader.model.SourceDetails;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import static burp.auto.vader.AutoVaderExtension.api;

/**
 * Parses JSON messages from the DOM Invader extension.
 */
public class DOMInvaderMessageParser {

    private final Gson gson = new Gson();
    private final DOMInvaderDataStore dataStore;

    public DOMInvaderMessageParser(DOMInvaderDataStore dataStore) {
        this.dataStore = dataStore;
    }

    /**
     * Parses and stores a message based on its type.
     *
     * @param json The JSON string containing the message data
     * @param type The type of message: "sink", "source", or "message"
     * @param url The URL from which the message originated
     * @return true if parsing and storage succeeded, false otherwise
     */
    public boolean parseAndStore(String json, String type, String url) {
        try {
            String origin = dataStore.extractOrigin(url);

            switch (type.toLowerCase()) {
                case "sink":
                    SinkDetails sink = gson.fromJson(json, SinkDetails.class);
                    dataStore.storeSink(origin, sink);
                    api.logging().logToOutput("Stored sink for origin: " + origin);
                    return true;

                case "source":
                    SourceDetails source = gson.fromJson(json, SourceDetails.class);
                    dataStore.storeSource(origin, source);
                    api.logging().logToOutput("Stored source for origin: " + origin);
                    return true;

                case "message":
                    MessageDetails message = gson.fromJson(json, MessageDetails.class);
                    dataStore.storeMessage(origin, message);
                    api.logging().logToOutput("Stored message for origin: " + origin);
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
}
