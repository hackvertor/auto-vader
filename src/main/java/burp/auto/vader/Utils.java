package burp.auto.vader;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class Utils {

    private static final String LETTERS = "abcdefghijklmnopqrstuvwxyz";
    private static final String ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyz0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Generates a random 10-character canary string.
     * First character is always a letter, remaining characters are alphanumeric.
     *
     * @return A random 10-character canary string
     */
    public static String generateCanary() {
        StringBuilder canary = new StringBuilder(10);

        // First character must be a letter
        canary.append(LETTERS.charAt(RANDOM.nextInt(LETTERS.length())));

        // Remaining 9 characters are alphanumeric
        for (int i = 1; i < 10; i++) {
            canary.append(ALPHANUMERIC.charAt(RANDOM.nextInt(ALPHANUMERIC.length())));
        }

        return canary.toString();
    }

    /**
     * Enumerates all query parameters in a URL and creates a list of URLs
     * with the canary injected into each parameter individually.
     *
     * For example:
     * Input: "http://example.com/page?x=123&y=456", canary: "abc123"
     * Output: ["http://example.com/page?x=abc123&y=456", "http://example.com/page?x=123&y=abc123"]
     *
     * @param url The original URL
     * @param canary The canary value to inject
     * @return List of URLs with canary injected into each parameter
     */
    public static List<String> enumerateQueryParameters(String url, String canary, String payload) {
        List<String> enumeratedUrls = new ArrayList<>();

        // Split URL into base and query string
        int queryStart = url.indexOf('?');
        if (queryStart == -1) {
            // No query parameters
            enumeratedUrls.add(url);
            return enumeratedUrls;
        }

        String baseUrl = url.substring(0, queryStart);
        String queryString = url.substring(queryStart + 1);

        // Handle fragment if present
        String fragment = "";
        int fragmentIndex = queryString.indexOf('#');
        if (fragmentIndex != -1) {
            fragment = queryString.substring(fragmentIndex);
            queryString = queryString.substring(0, fragmentIndex);
        }

        // Parse parameters
        String[] params = queryString.split("&");
        if (params.length == 0) {
            return enumeratedUrls;
        }

        // Create a URL for each parameter with canary injected
        for (int i = 0; i < params.length; i++) {
            StringBuilder newUrl = new StringBuilder(baseUrl).append("?");

            for (int j = 0; j < params.length; j++) {
                if (j > 0) {
                    newUrl.append("&");
                }

                String param = params[j];
                int equalsIndex = param.indexOf('=');

                if (j == i) {
                    // Inject canary into this parameter
                    if (equalsIndex != -1) {
                        String paramName = param.substring(0, equalsIndex);
                        newUrl.append(paramName).append("=").append(canary).append(payload);
                    } else {
                        // Parameter without value
                        newUrl.append(param).append("=").append(canary).append(payload);
                    }
                } else {
                    // Keep original parameter
                    newUrl.append(param);
                }
            }

            newUrl.append(fragment);
            enumeratedUrls.add(newUrl.toString());
        }

        return enumeratedUrls;
    }

    /**
     * Enumerates query parameters for multiple URLs.
     *
     * @param urls List of URLs to enumerate
     * @param canary The canary value to inject
     * @return List of all enumerated URLs
     */
    public static List<String> enumerateQueryParameters(List<String> urls, String canary, String payload) {
        List<String> allEnumeratedUrls = new ArrayList<>();

        for (String url : urls) {
            List<String> enumerated = enumerateQueryParameters(url, canary, payload);
            allEnumeratedUrls.addAll(enumerated);
        }

        return allEnumeratedUrls;
    }

    /**
     * Enumerates all POST parameters in an HTTP request and creates a list of HttpRequest objects
     * with the canary injected into each parameter individually.
     *
     * @param request The original HttpRequest
     * @param canary The canary value to inject
     * @param payload Additional payload to append after canary
     * @return List of HttpRequest objects with canary injected into each POST parameter
     */
    public static List<HttpRequest> enumeratePostParameters(HttpRequest request, String canary, String payload) {
        List<HttpRequest> enumeratedRequests = new ArrayList<>();

        // Get all body parameters (POST parameters)
        List<ParsedHttpParameter> bodyParams = request.parameters().stream().filter(param -> param.type() == HttpParameterType.BODY).toList();

        if (bodyParams.isEmpty()) {
            // No POST parameters
            return enumeratedRequests;
        }

        // Create a request for each parameter with canary injected
        for (int i = 0; i < bodyParams.size(); i++) {
            HttpRequest modifiedRequest = request;

            for (int j = 0; j < bodyParams.size(); j++) {
                HttpParameter param = bodyParams.get(j);

                if (j == i) {
                    // Inject canary into this parameter
                    String newValue = canary + payload;
                    modifiedRequest = modifiedRequest.withUpdatedParameters(
                        HttpParameter.parameter(param.name(), newValue, HttpParameterType.BODY)
                    );
                }
            }

            enumeratedRequests.add(modifiedRequest);
        }

        return enumeratedRequests;
    }

    /**
     * Enumerates POST parameters for multiple HTTP request/response pairs.
     *
     * @param requestResponses List of HttpRequestResponse objects
     * @param canary The canary value to inject
     * @param payload Additional payload to append after canary
     * @return List of all enumerated HttpRequest objects
     */
    public static List<HttpRequest> enumeratePostParameters(List<HttpRequestResponse> requestResponses,
                                                           String canary, String payload) {
        List<HttpRequest> allEnumeratedRequests = new ArrayList<>();

        for (HttpRequestResponse reqResp : requestResponses) {
            HttpRequest request = reqResp.request();
            List<HttpRequest> enumerated = enumeratePostParameters(request, canary, payload);
            allEnumeratedRequests.addAll(enumerated);
        }

        return allEnumeratedRequests;
    }

    public static void openUrl(String url) {
        if(url.startsWith("https://")) {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                try {
                    Desktop.getDesktop().browse(new URI(url));
                } catch (IOException ioException) {
                } catch (URISyntaxException uriSyntaxException) {

                }
            }
        }
    }
}
