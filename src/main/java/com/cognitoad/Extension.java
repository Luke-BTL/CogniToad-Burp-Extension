package com.cognitoad;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

public class Extension implements BurpExtension {
    private MontoyaApi montoyaApi;
    private CognitoTab cognitoTab;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        montoyaApi.extension().setName("CogniToad");
        
        // Create and register the Cognito tab
        cognitoTab = new CognitoTab(montoyaApi);
        montoyaApi.userInterface().registerSuiteTab("CogniToad", cognitoTab.getUiComponent());
        
        // Register context menu provider for access token extraction
        AccessTokenContextMenuProvider accessTokenContextMenuProvider = new AccessTokenContextMenuProvider(montoyaApi, cognitoTab);
        montoyaApi.userInterface().registerContextMenuItemsProvider(accessTokenContextMenuProvider);
        
        // Register context menu provider for user attributes extraction
        UserAttributesContextMenuProvider userAttributesContextMenuProvider = new UserAttributesContextMenuProvider(montoyaApi, cognitoTab);
        montoyaApi.userInterface().registerContextMenuItemsProvider(userAttributesContextMenuProvider);
        
        montoyaApi.logging().logToOutput("CogniToad extension loaded successfully");
        
        // Register unload handler
        montoyaApi.extension().registerUnloadingHandler(new ExtensionUnloadingHandler() {
            @Override
            public void extensionUnloaded() {
                if (cognitoTab != null) {
                    cognitoTab.cleanup();
                }
                montoyaApi.logging().logToOutput("CogniToad extension unloaded");
            }
        });
    }
}
