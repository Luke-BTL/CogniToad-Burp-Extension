package com.cognitoad;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Context menu provider that allows sending detected Identity Pool IDs
 * from the proxy history to the Identity Pool Tester tab.
 */
public class IdentityPoolIdContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi montoyaApi;
    private final CognitoTab cognitoTab;
    
    // Pattern to match AWS Cognito Identity Pool IDs: region:UUID format
    private static final Pattern IDENTITY_POOL_ID_PATTERN = Pattern.compile(
        "([a-z0-9-]+):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        Pattern.CASE_INSENSITIVE
    );

    public IdentityPoolIdContextMenuProvider(MontoyaApi montoyaApi, CognitoTab cognitoTab) {
        this.montoyaApi = montoyaApi;
        this.cognitoTab = cognitoTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        HttpRequestResponse requestResponse = null;

        // Use selected request/response context (works in list views: Proxy history, HTTP History, etc.)
        List<HttpRequestResponse> selections = event.selectedRequestResponses();
        if (!selections.isEmpty()) {
            requestResponse = selections.get(0);
        }

        if (requestResponse == null || requestResponse.response() == null) {
            return menuItems;
        }

        String responseBody = requestResponse.response().bodyToString();
        if (responseBody == null || responseBody.trim().isEmpty()) {
            return menuItems;
        }

        // Extract Identity Pool IDs from the response
        List<String> poolIds = extractIdentityPoolIds(responseBody);

        if (!poolIds.isEmpty()) {
            // If multiple IDs found, create a submenu
            if (poolIds.size() == 1) {
                final String poolId = poolIds.get(0);
                JMenuItem sendToTesterItem = new JMenuItem("Send Identity Pool ID to CogniToad");
                sendToTesterItem.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        cognitoTab.setIdentityPoolId(poolId);
                        montoyaApi.logging().logToOutput("Identity Pool ID sent to CogniToad extension: " + poolId);
                    }
                });
                menuItems.add(sendToTesterItem);
            } else {
                // Multiple IDs found - create submenu
                JMenu subMenu = new JMenu("Send Identity Pool ID to CogniToad");
                for (String poolId : poolIds) {
                    final String finalPoolId = poolId;
                    JMenuItem item = new JMenuItem(poolId);
                    item.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            cognitoTab.setIdentityPoolId(finalPoolId);
                            montoyaApi.logging().logToOutput("Identity Pool ID sent to CogniToad extension: " + finalPoolId);
                        }
                    });
                    subMenu.add(item);
                }
                menuItems.add(subMenu);
            }
        }

        return menuItems;
    }

    private List<String> extractIdentityPoolIds(String responseBody) {
        List<String> poolIds = new ArrayList<>();
        
        // Check if response contains JavaScript (either as a JS file or inline script)
        // We'll search for Identity Pool IDs in the response body
        Matcher matcher = IDENTITY_POOL_ID_PATTERN.matcher(responseBody);
        
        while (matcher.find()) {
            String identityPoolId = matcher.group(0);
            
            // Avoid duplicates
            if (!poolIds.contains(identityPoolId)) {
                poolIds.add(identityPoolId);
            }
        }
        
        return poolIds;
    }
}

