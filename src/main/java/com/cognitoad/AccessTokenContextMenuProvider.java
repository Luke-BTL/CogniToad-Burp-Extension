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

public class AccessTokenContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi montoyaApi;
    private final CognitoTab cognitoTab;

    public AccessTokenContextMenuProvider(MontoyaApi montoyaApi, CognitoTab cognitoTab) {
        this.montoyaApi = montoyaApi;
        this.cognitoTab = cognitoTab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        HttpRequestResponse requestResponse = null;
        
        // Try message editor context (HTTP History, Repeater message editors)
        // Note: This is complex due to obfuscated Burp classes, so we rely on selectedRequestResponses
        // which works when clicking in list views
        try {
            java.util.Optional<?> messageEditorOpt = event.messageEditorRequestResponse();
            if (messageEditorOpt.isPresent()) {
                Object messageEditor = messageEditorOpt.get();
                // Try to call requestResponse() method using reflection
                try {
                    java.lang.reflect.Method requestResponseMethod = messageEditor.getClass().getMethod("requestResponse");
                    Object reqResOptObj = requestResponseMethod.invoke(messageEditor);
                    
                    if (reqResOptObj instanceof java.util.Optional) {
                        java.util.Optional<?> reqResOpt = (java.util.Optional<?>) reqResOptObj;
                        if (reqResOpt.isPresent()) {
                            Object reqRes = reqResOpt.get();
                            if (reqRes instanceof HttpRequestResponse) {
                                requestResponse = (HttpRequestResponse) reqRes;
                            }
                        }
                    }
                } catch (Exception e) {
                    // Reflection failed - message editor access is limited in Montoya API
                    // This is expected for obfuscated Burp classes
                }
            }
        } catch (Exception e) {
            // Ignore - fall back to selectedRequestResponses
        }
        
        // Fall back to selected request/response context (works in list views: Proxy, HTTP History, etc.)
        if (requestResponse == null) {
            List<HttpRequestResponse> selections = event.selectedRequestResponses();
            if (!selections.isEmpty()) {
                requestResponse = selections.get(0);
            }
        }
        
        if (requestResponse == null) {
            return menuItems;
        }
        
        String accessToken = extractAccessToken(requestResponse);
        
        if (accessToken != null && !accessToken.isEmpty()) {
            final String finalToken = accessToken;
            JMenuItem sendToCognitoItem = new JMenuItem("Send access token to CogniToad extension");
            sendToCognitoItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    cognitoTab.setAccessToken(finalToken);
                    montoyaApi.logging().logToOutput("Access token sent to CogniToad extension");
                }
            });
            menuItems.add(sendToCognitoItem);
        }
        
        return menuItems;
    }

    private String extractAccessToken(HttpRequestResponse requestResponse) {
        try {
            // Prioritize response body (as user wants response body tokens)
            if (requestResponse.response() != null) {
                // Try response body first
                String responseBody = requestResponse.response().bodyToString();
                if (responseBody != null && !responseBody.trim().isEmpty()) {
                    String token = extractTokenFromJsonBody(responseBody);
                    if (token != null && !token.isEmpty()) {
                        return token;
                    }
                }
                
                // Fall back to response headers
                String token = extractTokenFromHeaders(requestResponse.response().toString());
                if (token != null && !token.isEmpty()) {
                    return token;
                }
            }
            
            // Fall back to request if no response token found
            if (requestResponse.request() != null) {
                String token = extractTokenFromHeaders(requestResponse.request().toString());
                if (token != null && !token.isEmpty()) {
                    return token;
                }
            }
        } catch (Exception e) {
            montoyaApi.logging().logToError("Error extracting access token: " + e.getMessage());
        }
        
        return null;
    }

    private String extractTokenFromJsonBody(String body) {
        // Pattern 1: "accessToken": "..." (camelCase - user's example)
        Pattern accessTokenPattern = Pattern.compile("\"accessToken\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
        Matcher accessTokenMatcher = accessTokenPattern.matcher(body);
        if (accessTokenMatcher.find()) {
            return accessTokenMatcher.group(1);
        }
        
        // Pattern 2: "access_token": "..." (snake_case)
        Pattern accessTokenSnakePattern = Pattern.compile("\"access_token\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
        Matcher accessTokenSnakeMatcher = accessTokenSnakePattern.matcher(body);
        if (accessTokenSnakeMatcher.find()) {
            return accessTokenSnakeMatcher.group(1);
        }
        
        // Pattern 3: "token": "..."
        Pattern tokenPattern = Pattern.compile("\"token\"\\s*:\\s*\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
        Matcher tokenMatcher = tokenPattern.matcher(body);
        if (tokenMatcher.find()) {
            return tokenMatcher.group(1);
        }
        
        return null;
    }

    private String extractTokenFromHeaders(String message) {
        // Pattern: Authorization: Bearer <token>
        // JWT tokens can contain: A-Za-z0-9._-+/=
        Pattern bearerPattern = Pattern.compile("(?i)Authorization:\\s*Bearer\\s+([A-Za-z0-9._\\-+/=]+)", Pattern.MULTILINE);
        Matcher bearerMatcher = bearerPattern.matcher(message);
        if (bearerMatcher.find()) {
            return bearerMatcher.group(1);
        }
        
        return null;
    }
}
