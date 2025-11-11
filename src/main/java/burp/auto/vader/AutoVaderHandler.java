package burp.auto.vader;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.auto.vader.actions.AutoVaderActions;

import java.util.List;

import static burp.auto.vader.AutoVaderExtension.*;
import static burp.auto.vader.actions.AutoVaderActions.createScanProfile;

public class AutoVaderHandler implements HttpHandler {

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        boolean isFromRepeater = req.toolSource().isFromTool(ToolType.REPEATER);
        boolean isFromIntruder = req.toolSource().isFromTool(ToolType.INTRUDER);
        boolean isFromExtensions = req.toolSource().isFromTool(ToolType.EXTENSIONS);
        boolean shouldRunFromRepeater = settings.getBoolean("Auto run from Repeater");
        boolean shouldRunFromIntruder = settings.getBoolean("Auto run from Intruder");
        boolean shouldRunFromOtherExtensions = settings.getBoolean("Auto run from other extensions");

        boolean shouldExecute = (shouldRunFromRepeater && isFromRepeater) ||
                                (shouldRunFromIntruder && isFromIntruder) ||
                                (shouldRunFromOtherExtensions && isFromExtensions);

        if(shouldExecute) {
            executorService.submit(
              () -> {
                String domInvaderPath = AutoVaderExtension.domInvaderPath;
                String canary = projectCanary;
                if (!req.isInScope()) return;
                String reqStr = req.toString();
                if(!reqStr.contains("$canary")) return;
                reqStr = reqStr.replace("$canary", canary);
                boolean isHeadless = settings.getBoolean("Headless");
                DOMInvaderConfig.Profile profile =
                    createScanProfile(canary, AutoVaderActions.ScanType.QUERY_PARAMS);
                int delay = settings.getInteger("Delay MS");
                new PlaywrightRenderer(new DOMInvaderConfig(profile), deduper, false)
                    .renderHttpRequests(List.of(HttpRequest.httpRequest(req.httpService(), reqStr)), domInvaderPath, true, isHeadless, true, delay);
              });
        }
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        return null;
    }
}
