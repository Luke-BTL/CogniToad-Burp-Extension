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

public class UserAttributesContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi montoyaApi;
    private final CognitoTab cognitoTab;

    public UserAttributesContextMenuProvider(MontoyaApi montoyaApi, CognitoTab cognitoTab) {
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

        // Try to extract user attributes from the response
        java.util.Map.Entry<java.util.List<String>, java.util.List<String>> attributes = extractUserAttributes(responseBody);

        if (attributes != null && (!attributes.getKey().isEmpty() || !attributes.getValue().isEmpty())) {
            final java.util.List<String> keys = attributes.getKey();
            final java.util.List<String> values = attributes.getValue();
            
            JMenuItem sendToCognitoItem = new JMenuItem("Send user attributes to CogniToad extension");
            sendToCognitoItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    cognitoTab.populateUserAttributes(keys, values);
                    montoyaApi.logging().logToOutput("User attributes sent to CogniToad extension");
                }
            });
            menuItems.add(sendToCognitoItem);
        }

        return menuItems;
    }

    private java.util.Map.Entry<java.util.List<String>, java.util.List<String>> extractUserAttributes(String responseBody) {
        java.util.List<String> keys = new java.util.ArrayList<>();
        java.util.List<String> values = new java.util.ArrayList<>();
        
        try {
            // First, try to find UserAttributes array (AWS Cognito format)
            Pattern userAttributesPattern = Pattern.compile(
                "\"UserAttributes\"\\s*:\\s*\\[(.*?)\\]",
                Pattern.DOTALL | Pattern.CASE_INSENSITIVE
            );
            Matcher userAttributesMatcher = userAttributesPattern.matcher(responseBody);
            
            if (userAttributesMatcher.find()) {
                String attributesArrayContent = userAttributesMatcher.group(1);
                
                // Extract individual attribute objects: {"Name": "...", "Value": "..."}
                Pattern attrPattern = Pattern.compile(
                    "\\{\\s*\"Name\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"Value\"\\s*:\\s*\"([^\"]*)\"\\s*\\}|" +
                    "\\{\\s*\"Value\"\\s*:\\s*\"([^\"]*)\"\\s*,\\s*\"Name\"\\s*:\\s*\"([^\"]+)\"\\s*\\}",
                    Pattern.DOTALL
                );
                Matcher attrMatcher = attrPattern.matcher(attributesArrayContent);
                
                while (attrMatcher.find()) {
                    String name, value;
                    if (attrMatcher.group(1) != null) {
                        name = attrMatcher.group(1);
                        value = attrMatcher.group(2);
                    } else {
                        value = attrMatcher.group(3);
                        name = attrMatcher.group(4);
                    }
                    
                    if (name != null && !name.isEmpty()) {
                        if (!keys.contains(name)) {
                            keys.add(name);
                        }
                        if (value != null && !value.isEmpty() && !values.contains(value)) {
                            values.add(value);
                        }
                    }
                }
            } else {
                // Extract key-value pairs from JSON objects (generic format)
                // Pattern to match: "key": "value" where value is a string
                Pattern kvPattern = Pattern.compile(
                    "\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\""
                );
                Matcher kvMatcher = kvPattern.matcher(responseBody);
                
                // Fields to skip (metadata/token fields)
                java.util.Set<String> skipFields = new java.util.HashSet<>();
                skipFields.add("accessToken");
                skipFields.add("tokenType");
                skipFields.add("expiresIn");
                skipFields.add("expiresAt");
                skipFields.add("scope");
                skipFields.add("client");
                skipFields.add("cognitoToken");
                skipFields.add("impersonatorContext");
                skipFields.add("authenticationExtras");
                skipFields.add("secondaryUcrns");
                skipFields.add("partyIds");
                
                while (kvMatcher.find()) {
                    String key = kvMatcher.group(1);
                    String value = kvMatcher.group(2);
                    
                    if (key != null && !key.isEmpty() && !skipFields.contains(key.toLowerCase())) {
                        if (!keys.contains(key)) {
                            keys.add(key);
                        }
                        if (value != null && !value.isEmpty() && !value.equals("null") && !values.contains(value)) {
                            values.add(value);
                        }
                    }
                }
            }
        } catch (Exception e) {
            montoyaApi.logging().logToError("Error extracting user attributes: " + e.getMessage());
        }
        
        if (keys.isEmpty() && values.isEmpty()) {
            return null;
        }
        
        return new java.util.AbstractMap.SimpleEntry<>(keys, values);
    }
}
