package com.cognitoad;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.InterceptedResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Proxy response handler that highlights requests in the proxy list when 
 * AWS Cognito Identity Pool IDs are detected in responses.
 */
public class CognitoIdentityPoolIdProxyHandler implements ProxyResponseHandler {
    private final MontoyaApi montoyaApi;
    
    // Pattern to match AWS Cognito Identity Pool IDs: region:UUID format
    // Examples: us-east-1:12345678-1234-1234-1234-123456789abc
    //           eu-west-2:abcdef12-3456-7890-abcd-ef1234567890
    private static final Pattern IDENTITY_POOL_ID_PATTERN = Pattern.compile(
        "([a-z0-9-]+):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        Pattern.CASE_INSENSITIVE
    );
    
    public CognitoIdentityPoolIdProxyHandler(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
    }
    
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        // Get response body as string
        String responseBody = interceptedResponse.bodyToString();
        if (responseBody == null || responseBody.isEmpty()) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
        
        // Check if response contains JavaScript (either as a JS file or inline script)
        String contentType = interceptedResponse.statedMimeType() != null ? 
            interceptedResponse.statedMimeType().toString() : "";
        boolean isJavaScript = contentType.contains("javascript") || 
            contentType.contains("text/javascript") || 
            contentType.contains("application/javascript");
        
        // Also check for inline scripts in HTML
        boolean hasInlineScript = responseBody.contains("<script") || responseBody.contains("</script>");
        
        // Only scan JavaScript files or HTML with inline scripts
        if (!isJavaScript && !hasInlineScript) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }
        
        // Search for Identity Pool IDs
        Matcher matcher = IDENTITY_POOL_ID_PATTERN.matcher(responseBody);
        List<String> foundIds = new ArrayList<>();
        
        while (matcher.find()) {
            String identityPoolId = matcher.group(0);
            
            // Avoid duplicates
            if (!foundIds.contains(identityPoolId)) {
                foundIds.add(identityPoolId);
            }
        }
        
        // If Identity Pool IDs were found, highlight the request in the proxy list
        if (!foundIds.isEmpty()) {
            // Create annotations with highlight color and note
            String note = "Cognito Identity Pool ID detected: " + String.join(", ", foundIds);
            Annotations annotations = Annotations.annotations(note, HighlightColor.ORANGE);
            
            // Return response with annotations to highlight the entry in proxy list
            return ProxyResponseReceivedAction.continueWith(interceptedResponse, annotations);
        }
        
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }
    
    @Override
    public burp.api.montoya.proxy.http.ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        // No modification needed when sending response
        return burp.api.montoya.proxy.http.ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }
}

