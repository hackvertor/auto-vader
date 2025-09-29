package burp.auto.vader;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.auto.vader.ui.AutoVaderContextMenu;

public class AutoVaderExtension implements BurpExtension
{
    public static MontoyaApi api;
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Auto Vader v1.0.0");
        AutoVaderExtension.api = api;
        api.userInterface().registerContextMenuItemsProvider(new AutoVaderContextMenu());
    }
}