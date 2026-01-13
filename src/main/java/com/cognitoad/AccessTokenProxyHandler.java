package com.cognitoad;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Proxy handler that highlights requests and responses in the proxy list when 
 * access tokens are detected in JSON bodies (accessToken, access_token).
 */
public class AccessTokenProxyHandler implements ProxyRequestHandler, ProxyResponseHandler {
    private final MontoyaApi montoyaApi;
    
    // Pattern 1: "accessToken": "..." (camelCase)
    private static final Pattern ACCESS_TOKEN_PATTERN = Pattern.compile(
        "\"accessToken\"\\s*:\\s*\"([^\"]+)\"", 
        Pattern.CASE_INSENSITIVE
    );
    
    // Pattern 2: "access_token": "..." (snake_case)
    private static final Pattern ACCESS_TOKEN_SNAKE_PATTERN = Pattern.compile(
        "\"access_token\"\\s*:\\s*\"([^\"]+)\"", 
        Pattern.CASE_INSENSITIVE
    );
    
    public AccessTokenProxyHandler(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
    }
    
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        // Only check request body for access tokens in JSON, not headers
        String requestBody = interceptedRequest.bodyToString();
        if (requestBody != null && !requestBody.isEmpty()) {
            List<String> tokens = findTokensInJsonBody(requestBody);
            if (!tokens.isEmpty()) {
                String note = "Access token detected in request: " + maskToken(tokens.get(0));
                Annotations annotations = Annotations.annotations(note, HighlightColor.YELLOW);
                return ProxyRequestReceivedAction.continueWith(interceptedRequest, annotations);
            }
        }
        
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }
    
    @Override
    public burp.api.montoya.proxy.http.ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        // No modification needed when sending request
        return burp.api.montoya.proxy.http.ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }
    
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        // Check response body for access tokens in JSON only
        String responseBody = interceptedResponse.bodyToString();
        if (responseBody != null && !responseBody.isEmpty()) {
            List<String> foundTokens = findTokensInJsonBody(responseBody);
            
            // If tokens were found, highlight the request in the proxy list
            if (!foundTokens.isEmpty()) {
                String note = "Access token detected: " + maskToken(foundTokens.get(0));
                if (foundTokens.size() > 1) {
                    note += " (+" + (foundTokens.size() - 1) + " more)";
                }
                Annotations annotations = Annotations.annotations(note, HighlightColor.RED);
                return ProxyResponseReceivedAction.continueWith(interceptedResponse, annotations);
            }
        }
        
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }
    
    @Override
    public burp.api.montoya.proxy.http.ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        // No modification needed when sending response
        return burp.api.montoya.proxy.http.ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
    
    private List<String> findTokensInJsonBody(String body) {
        List<String> tokens = new ArrayList<>();
        
        // Check for accessToken
        Matcher matcher = ACCESS_TOKEN_PATTERN.matcher(body);
        while (matcher.find()) {
            String token = matcher.group(1);
            if (token != null && !token.isEmpty() && !tokens.contains(token)) {
                tokens.add(token);
            }
        }
        
        // Check for access_token
        matcher = ACCESS_TOKEN_SNAKE_PATTERN.matcher(body);
        while (matcher.find()) {
            String token = matcher.group(1);
            if (token != null && !token.isEmpty() && !tokens.contains(token)) {
                tokens.add(token);
            }
        }
        
        return tokens;
    }
    
    private String maskToken(String token) {
        if (token == null || token.length() <= 8) {
            return "***";
        }
        return token.substring(0, 4) + "..." + token.substring(token.length() - 4);
    }
}

