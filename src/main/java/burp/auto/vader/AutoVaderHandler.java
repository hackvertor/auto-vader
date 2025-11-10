package burp.auto.vader;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;

import static burp.auto.vader.AutoVaderExtension.settings;

public class AutoVaderHandler implements HttpHandler {

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        boolean isFromRepeater = req.toolSource().isFromTool(ToolType.REPEATER);
        boolean isFromIntruder = req.toolSource().isFromTool(ToolType.INTRUDER);
        boolean shouldRunFromRepeater = settings.getBoolean("Auto run from Repeater");
        boolean shouldRunFromIntruder = settings.getBoolean("Auto run from Intruder");
        if(shouldRunFromRepeater && isFromRepeater) {

        }
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        return null;
    }
}
