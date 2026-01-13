package com.cognitoad;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive scanner that detects exposed AWS Cognito Identity Pool IDs in JavaScript or inline scripts.
 * Pattern: UUID format like us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 */
public class CognitoIdentityPoolIdScanner implements ScanCheck {
    private final MontoyaApi montoyaApi;
    
    // Pattern to match AWS Cognito Identity Pool IDs: region:UUID format
    // Examples: us-east-1:12345678-1234-1234-1234-123456789abc
    //           eu-west-2:abcdef12-3456-7890-abcd-ef1234567890
    private static final Pattern IDENTITY_POOL_ID_PATTERN = Pattern.compile(
        "([a-z0-9-]+):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        Pattern.CASE_INSENSITIVE
    );
    
    public CognitoIdentityPoolIdScanner(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
    }
    
    @Override
    public AuditResult passiveAudit(HttpRequestResponse requestResponse) {
        List<AuditIssue> issues = new ArrayList<>();
        HttpResponse response = requestResponse.response();
        
        if (response == null) {
            return AuditResult.auditResult(issues);
        }
        
        // Get response body as string
        String responseBody = response.bodyToString();
        if (responseBody == null || responseBody.isEmpty()) {
            return AuditResult.auditResult(issues);
        }
        
        // Check if response contains JavaScript (either as a JS file or inline script)
        String contentType = response.statedMimeType() != null ? response.statedMimeType().toString() : "";
        boolean isJavaScript = contentType.contains("javascript") || 
            contentType.contains("text/javascript") || 
            contentType.contains("application/javascript");
        
        // Also check for inline scripts in HTML
        boolean hasInlineScript = responseBody.contains("<script") || responseBody.contains("</script>");
        
        // Only scan JavaScript files or HTML with inline scripts
        if (!isJavaScript && !hasInlineScript) {
            return AuditResult.auditResult(issues);
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
        
        // Create issues for each found Identity Pool ID
        for (String identityPoolId : foundIds) {
            AuditIssue issue = AuditIssue.auditIssue(
                "Exposed AWS Cognito Identity Pool ID",
                "The response contains an exposed AWS Cognito Identity Pool ID: " + identityPoolId + 
                "\n\nIdentity Pool IDs should not be exposed in client-side code as they can be used to " +
                "identify the AWS Cognito Identity Pool and potentially be misused.",
                "Remove the Identity Pool ID from client-side code. Use environment variables or " +
                "server-side configuration instead.",
                requestResponse.request().url(),
                AuditIssueSeverity.LOW,
                AuditIssueConfidence.CERTAIN,
                null,
                null,
                null,
                requestResponse
            );
            
            issues.add(issue);
        }
        
        return AuditResult.auditResult(issues);
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

