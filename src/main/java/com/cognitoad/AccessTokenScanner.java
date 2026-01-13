package com.cognitoad;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive scanner that detects exposed access tokens in HTTP requests and responses.
 * Detects tokens in JSON bodies ("accessToken", "access_token").
 */
public class AccessTokenScanner implements ScanCheck {
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
    
    public AccessTokenScanner(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
    }
    
    @Override
    public AuditResult passiveAudit(HttpRequestResponse requestResponse) {
        List<AuditIssue> issues = new ArrayList<>();
        
        // Check response body for access tokens in JSON
        if (requestResponse.response() != null) {
            HttpResponse response = requestResponse.response();
            String responseBody = response.bodyToString();
            
            if (responseBody != null && !responseBody.isEmpty()) {
                // Check if response is JSON or contains JSON-like content
                String contentType = response.statedMimeType() != null ? 
                    response.statedMimeType().toString() : "";
                boolean isJson = contentType.contains("json") || 
                    contentType.contains("application/json") ||
                    (responseBody.trim().startsWith("{") && responseBody.trim().endsWith("}")) ||
                    (responseBody.trim().startsWith("[") && responseBody.trim().endsWith("]"));
                
                // Only scan if it looks like JSON
                if (isJson) {
                    // Check JSON body for tokens
                    List<String> foundTokens = findTokensInJsonBody(responseBody);
                    if (!foundTokens.isEmpty()) {
                        montoyaApi.logging().logToOutput("AccessTokenScanner: Found " + foundTokens.size() + " access token(s) in response from " + requestResponse.request().url());
                    }
                    for (String token : foundTokens) {
                        AuditIssue issue = AuditIssue.auditIssue(
                            "Exposed Access Token in Response",
                            "The response contains an exposed access token: " + maskToken(token) + 
                            "\n\nAccess tokens should not be exposed in client-side code or responses as they " +
                            "can be used to authenticate as the user.",
                            "Remove the access token from the response. Use secure, httpOnly cookies or " +
                            "server-side session management instead.",
                            requestResponse.request().url(),
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.CERTAIN,
                            null,
                            null,
                            null,
                            requestResponse
                        );
                        issues.add(issue);
                    }
                }
            }
        }
        
        // Check request body for access tokens in JSON
        if (requestResponse.request() != null) {
            HttpRequest request = requestResponse.request();
            String requestBody = request.bodyToString();
            
            if (requestBody != null && !requestBody.isEmpty()) {
                // Check if request body looks like JSON
                boolean isJson = (requestBody.trim().startsWith("{") && requestBody.trim().endsWith("}")) ||
                    (requestBody.trim().startsWith("[") && requestBody.trim().endsWith("]"));
                
                if (isJson) {
                    List<String> foundTokens = findTokensInJsonBody(requestBody);
                    for (String token : foundTokens) {
                        AuditIssue issue = AuditIssue.auditIssue(
                            "Exposed Access Token in Request",
                            "The request contains an exposed access token: " + maskToken(token) + 
                            "\n\nWhile tokens in requests may be expected, ensure they are not logged or exposed in error messages.",
                            "Ensure access tokens are not logged, cached, or exposed in error responses.",
                            requestResponse.request().url(),
                            AuditIssueSeverity.INFORMATION,
                            AuditIssueConfidence.CERTAIN,
                            null,
                            null,
                            null,
                            requestResponse
                        );
                        issues.add(issue);
                    }
                }
            }
        }
        
        return AuditResult.auditResult(issues);
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
    
    @Override
    public AuditResult activeAudit(HttpRequestResponse requestResponse, AuditInsertionPoint insertionPoint) {
        // This is a passive scanner only, no active scanning
        return AuditResult.auditResult();
    }
    
    @Override
    public burp.api.montoya.scanner.ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        // Use default consolidation behavior
        return burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
    }
}

