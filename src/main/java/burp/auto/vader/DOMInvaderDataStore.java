package burp.auto.vader;

import burp.auto.vader.model.MessageDetails;
import burp.auto.vader.model.SinkDetails;
import burp.auto.vader.model.SourceDetails;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe storage for DOM Invader data organized by URL origin.
 */
public class DOMInvaderDataStore {

    private final ConcurrentHashMap<String, OriginData> dataByOrigin = new ConcurrentHashMap<>();

    public static class OriginData {
        private final List<SinkDetails> sinks = new ArrayList<>();
        private final List<SourceDetails> sources = new ArrayList<>();
        private final List<MessageDetails> messages = new ArrayList<>();

        public synchronized void addSink(SinkDetails sink) {
            sinks.add(sink);
        }

        public synchronized void addSource(SourceDetails source) {
            sources.add(source);
        }

        public synchronized void addMessage(MessageDetails message) {
            messages.add(message);
        }

        public synchronized List<SinkDetails> getSinks() {
            return new ArrayList<>(sinks);
        }

        public synchronized List<SourceDetails> getSources() {
            return new ArrayList<>(sources);
        }

        public synchronized List<MessageDetails> getMessages() {
            return new ArrayList<>(messages);
        }

        public synchronized int getTotalCount() {
            return sinks.size() + sources.size() + messages.size();
        }
    }

    /**
     * Extracts the origin (scheme + host + port) from a URL.
     */
    public String extractOrigin(String url) {
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            int port = uri.getPort();

            if (scheme == null || host == null) {
                return url; // fallback to full URL if parsing fails
            }

            StringBuilder origin = new StringBuilder();
            origin.append(scheme).append("://").append(host);

            // Only include port if it's not the default for the scheme
            if (port != -1 &&
                !((scheme.equals("http") && port == 80) ||
                  (scheme.equals("https") && port == 443))) {
                origin.append(":").append(port);
            }

            return origin.toString();
        } catch (URISyntaxException e) {
            return url; // fallback to full URL if parsing fails
        }
    }

    /**
     * Stores a sink for the given origin.
     */
    public void storeSink(String origin, SinkDetails sink) {
        dataByOrigin.computeIfAbsent(origin, k -> new OriginData()).addSink(sink);
    }

    /**
     * Stores a source for the given origin.
     */
    public void storeSource(String origin, SourceDetails source) {
        dataByOrigin.computeIfAbsent(origin, k -> new OriginData()).addSource(source);
    }

    /**
     * Stores a message for the given origin.
     */
    public void storeMessage(String origin, MessageDetails message) {
        dataByOrigin.computeIfAbsent(origin, k -> new OriginData()).addMessage(message);
    }

    /**
     * Gets all data for a specific origin.
     */
    public OriginData getDataForOrigin(String origin) {
        return dataByOrigin.get(origin);
    }

    /**
     * Gets all origins that have data.
     */
    public List<String> getAllOrigins() {
        return new ArrayList<>(dataByOrigin.keySet());
    }

    /**
     * Clears all data for a specific origin.
     */
    public void clearOrigin(String origin) {
        dataByOrigin.remove(origin);
    }

    /**
     * Clears all data.
     */
    public void clearAll() {
        dataByOrigin.clear();
    }
}
