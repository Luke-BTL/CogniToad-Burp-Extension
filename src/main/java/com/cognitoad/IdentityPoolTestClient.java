package com.cognitoad;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Client for testing AWS Cognito Identity Pool security.
 * Tests for unauthenticated access, privilege escalation, and overprivileged roles.
 */
public class IdentityPoolTestClient {
    private final MontoyaApi montoyaApi;
    
    public IdentityPoolTestClient(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
    }
    
    /**
     * Test GetId without authentication
     */
    public TestResult testGetIdUnauthenticated(String identityPoolId, String region) {
        try {
            String host = "cognito-identity." + region + ".amazonaws.com";
            HttpService httpService = HttpService.httpService(host, 443, true);
            
            String requestBody = "{\"IdentityPoolId\":\"" + escapeJson(identityPoolId) + "\"}";
            
            StringBuilder requestBuilder = new StringBuilder();
            requestBuilder.append("POST / HTTP/1.1\r\n");
            requestBuilder.append("Host: ").append(host).append("\r\n");
            requestBuilder.append("Content-Type: application/x-amz-json-1.1\r\n");
            requestBuilder.append("X-Amz-Target: AWSCognitoIdentityService.GetId\r\n");
            requestBuilder.append("Content-Length: ").append(requestBody.length()).append("\r\n");
            requestBuilder.append("\r\n");
            requestBuilder.append(requestBody);
            
            ByteArray requestBytes = ByteArray.byteArray(requestBuilder.toString().getBytes(StandardCharsets.UTF_8));
            HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
            HttpResponse response = montoyaApi.http().sendRequest(request).response();
            
            return new TestResult(
                response.statusCode() == 200,
                response.statusCode(),
                formatResponse(request, response),
                response.bodyToString(),
                formatRequest(request),
                formatResponseOnly(response),
                request,
                response
            );
        } catch (Exception e) {
            return new TestResult(false, 0, "Error: " + e.getMessage(), null, 
                "Error: " + e.getMessage(), null, null, null);
        }
    }
    
    /**
     * Test GetCredentialsForIdentity without authentication
     */
    public TestResult testGetCredentialsUnauthenticated(String identityId, String region) {
        try {
            String host = "cognito-identity." + region + ".amazonaws.com";
            HttpService httpService = HttpService.httpService(host, 443, true);
            
            String requestBody = "{\"IdentityId\":\"" + escapeJson(identityId) + "\"}";
            
            StringBuilder requestBuilder = new StringBuilder();
            requestBuilder.append("POST / HTTP/1.1\r\n");
            requestBuilder.append("Host: ").append(host).append("\r\n");
            requestBuilder.append("Content-Type: application/x-amz-json-1.1\r\n");
            requestBuilder.append("X-Amz-Target: AWSCognitoIdentityService.GetCredentialsForIdentity\r\n");
            requestBuilder.append("Content-Length: ").append(requestBody.length()).append("\r\n");
            requestBuilder.append("\r\n");
            requestBuilder.append(requestBody);
            
            ByteArray requestBytes = ByteArray.byteArray(requestBuilder.toString().getBytes(StandardCharsets.UTF_8));
            HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
            HttpResponse response = montoyaApi.http().sendRequest(request).response();
            
            return new TestResult(
                response.statusCode() == 200,
                response.statusCode(),
                formatResponse(request, response),
                response.bodyToString(),
                formatRequest(request),
                formatResponseOnly(response),
                request,
                response
            );
        } catch (Exception e) {
            return new TestResult(false, 0, "Error: " + e.getMessage(), null, 
                "Error: " + e.getMessage(), null, null, null);
        }
    }
    
    /**
     * Test STS GetCallerIdentity using temporary credentials
     */
    public TestResult testSTSGetCallerIdentity(String accessKeyId, String secretAccessKey, String sessionToken, String region) {
        try {
            String host = "sts." + region + ".amazonaws.com";
            HttpService httpService = HttpService.httpService(host, 443, true);
            
            String path = "/";
            // STS uses query string parameters, not body
            String queryString = "Action=GetCallerIdentity&Version=2011-06-15";
            String requestBody = ""; // Empty body for STS query string requests
            
            // Prepare headers for signing
            Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            headers.put("host", host);
            if (sessionToken != null && !sessionToken.isEmpty()) {
                headers.put("x-amz-security-token", sessionToken);
            }
            
            // Sign the request (query string in URL, empty body)
            AWSSignatureV4.SigningResult signingResult = AWSSignatureV4.signRequestWithDate(
                "POST", host, path, queryString, headers, requestBody,
                accessKeyId, secretAccessKey, sessionToken, region, "sts"
            );
            headers.put("authorization", signingResult.authorization);
            headers.put("x-amz-date", signingResult.amzDate);
            
            // Build request with query string in URL
            StringBuilder requestBuilder = new StringBuilder();
            requestBuilder.append("POST ").append(path).append("?").append(queryString).append(" HTTP/1.1\r\n");
            requestBuilder.append("Host: ").append(host).append("\r\n");
            // Output headers in sorted order
            for (Map.Entry<String, String> header : headers.entrySet()) {
                if (!header.getKey().equalsIgnoreCase("host")) {
                    requestBuilder.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
                }
            }
            requestBuilder.append("\r\n");
            
            ByteArray requestBytes = ByteArray.byteArray(requestBuilder.toString().getBytes(StandardCharsets.UTF_8));
            HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
            HttpResponse response = montoyaApi.http().sendRequest(request).response();
            
            return new TestResult(
                response.statusCode() == 200,
                response.statusCode(),
                formatResponse(request, response),
                response.bodyToString(),
                formatRequest(request),
                formatResponseOnly(response),
                request,
                response
            );
        } catch (Exception e) {
            return new TestResult(false, 0, "Error: " + e.getMessage(), null, 
                "Error: " + e.getMessage(), null, null, null);
        }
    }
    
    /**
     * Test S3 ListBuckets using temporary credentials
     */
    public TestResult testS3ListBuckets(String accessKeyId, String secretAccessKey, String sessionToken, String region) {
        try {
            String host = "s3." + region + ".amazonaws.com";
            HttpService httpService = HttpService.httpService(host, 443, true);
            
            String path = "/";
            String queryString = "";
            String requestBody = "";
            
            // Prepare headers for signing
            Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            headers.put("host", host);
            if (sessionToken != null && !sessionToken.isEmpty()) {
                headers.put("x-amz-security-token", sessionToken);
            }
            
            // Sign the request
            AWSSignatureV4.SigningResult signingResult = AWSSignatureV4.signRequestWithDate(
                "GET", host, path, queryString, headers, requestBody,
                accessKeyId, secretAccessKey, sessionToken, region, "s3"
            );
            headers.put("authorization", signingResult.authorization);
            headers.put("x-amz-date", signingResult.amzDate);
            
            // Build request
            StringBuilder requestBuilder = new StringBuilder();
            requestBuilder.append("GET ").append(path).append(" HTTP/1.1\r\n");
            requestBuilder.append("Host: ").append(host).append("\r\n");
            for (Map.Entry<String, String> header : headers.entrySet()) {
                if (!header.getKey().equalsIgnoreCase("host")) {
                    requestBuilder.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
                }
            }
            requestBuilder.append("\r\n");
            
            ByteArray requestBytes = ByteArray.byteArray(requestBuilder.toString().getBytes(StandardCharsets.UTF_8));
            HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
            HttpResponse response = montoyaApi.http().sendRequest(request).response();
            
            return new TestResult(
                response.statusCode() == 200,
                response.statusCode(),
                formatResponse(request, response),
                response.bodyToString(),
                formatRequest(request),
                formatResponseOnly(response),
                request,
                response
            );
        } catch (Exception e) {
            return new TestResult(false, 0, "Error: " + e.getMessage(), null, 
                "Error: " + e.getMessage(), null, null, null);
        }
    }
    
    /**
     * Test DynamoDB ListTables using temporary credentials
     */
    public TestResult testDynamoDBListTables(String accessKeyId, String secretAccessKey, String sessionToken, String region) {
        try {
            String host = "dynamodb." + region + ".amazonaws.com";
            HttpService httpService = HttpService.httpService(host, 443, true);
            
            String path = "/";
            String queryString = "";
            String requestBody = "{\"Limit\":100}";
            
            // Prepare headers for signing
            Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            headers.put("host", host);
            headers.put("content-type", "application/x-amz-json-1.0");
            headers.put("x-amz-target", "DynamoDB_20120810.ListTables");
            if (sessionToken != null && !sessionToken.isEmpty()) {
                headers.put("x-amz-security-token", sessionToken);
            }
            
            // Sign the request
            AWSSignatureV4.SigningResult signingResult = AWSSignatureV4.signRequestWithDate(
                "POST", host, path, queryString, headers, requestBody,
                accessKeyId, secretAccessKey, sessionToken, region, "dynamodb"
            );
            headers.put("authorization", signingResult.authorization);
            headers.put("x-amz-date", signingResult.amzDate);
            
            // Build request
            StringBuilder requestBuilder = new StringBuilder();
            requestBuilder.append("POST ").append(path).append(" HTTP/1.1\r\n");
            requestBuilder.append("Host: ").append(host).append("\r\n");
            for (Map.Entry<String, String> header : headers.entrySet()) {
                if (!header.getKey().equalsIgnoreCase("host")) {
                    requestBuilder.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
                }
            }
            requestBuilder.append("Content-Length: ").append(requestBody.length()).append("\r\n");
            requestBuilder.append("\r\n");
            requestBuilder.append(requestBody);
            
            ByteArray requestBytes = ByteArray.byteArray(requestBuilder.toString().getBytes(StandardCharsets.UTF_8));
            HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
            HttpResponse response = montoyaApi.http().sendRequest(request).response();
            
            return new TestResult(
                response.statusCode() == 200,
                response.statusCode(),
                formatResponse(request, response),
                response.bodyToString(),
                formatRequest(request),
                formatResponseOnly(response),
                request,
                response
            );
        } catch (Exception e) {
            return new TestResult(false, 0, "Error: " + e.getMessage(), null, 
                "Error: " + e.getMessage(), null, null, null);
        }
    }
    
    /**
     * Test Lambda ListFunctions using temporary credentials
     */
    public TestResult testLambdaListFunctions(String accessKeyId, String secretAccessKey, String sessionToken, String region) {
        try {
            String host = "lambda." + region + ".amazonaws.com";
            HttpService httpService = HttpService.httpService(host, 443, true);
            
            String path = "/";
            String queryString = "";
            String requestBody = "{}";
            
            // Prepare headers for signing
            Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            headers.put("host", host);
            headers.put("content-type", "application/x-amz-json-1.0");
            headers.put("x-amz-target", "AWSLambda.ListFunctions");
            if (sessionToken != null && !sessionToken.isEmpty()) {
                headers.put("x-amz-security-token", sessionToken);
            }
            
            // Sign the request
            AWSSignatureV4.SigningResult signingResult = AWSSignatureV4.signRequestWithDate(
                "POST", host, path, queryString, headers, requestBody,
                accessKeyId, secretAccessKey, sessionToken, region, "lambda"
            );
            headers.put("authorization", signingResult.authorization);
            headers.put("x-amz-date", signingResult.amzDate);
            
            // Build request
            StringBuilder requestBuilder = new StringBuilder();
            requestBuilder.append("POST ").append(path).append(" HTTP/1.1\r\n");
            requestBuilder.append("Host: ").append(host).append("\r\n");
            for (Map.Entry<String, String> header : headers.entrySet()) {
                if (!header.getKey().equalsIgnoreCase("host")) {
                    requestBuilder.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
                }
            }
            requestBuilder.append("Content-Length: ").append(requestBody.length()).append("\r\n");
            requestBuilder.append("\r\n");
            requestBuilder.append(requestBody);
            
            ByteArray requestBytes = ByteArray.byteArray(requestBuilder.toString().getBytes(StandardCharsets.UTF_8));
            HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
            HttpResponse response = montoyaApi.http().sendRequest(request).response();
            
            return new TestResult(
                response.statusCode() == 200,
                response.statusCode(),
                formatResponse(request, response),
                response.bodyToString(),
                formatRequest(request),
                formatResponseOnly(response),
                request,
                response
            );
        } catch (Exception e) {
            return new TestResult(false, 0, "Error: " + e.getMessage(), null, 
                "Error: " + e.getMessage(), null, null, null);
        }
    }
    
    /**
     * Test GetOpenIdTokenForDeveloperIdentity with arbitrary Logins
     */
    public TestResult testDeveloperIdentityAbuse(String identityPoolId, String region) {
        try {
            String host = "cognito-identity." + region + ".amazonaws.com";
            HttpService httpService = HttpService.httpService(host, 443, true);
            
            // Try with arbitrary logins parameter
            String requestBody = "{\"IdentityPoolId\":\"" + escapeJson(identityPoolId) + 
                "\",\"Logins\":{\"arbitrary.provider\":\"test@example.com\"}}";
            
            StringBuilder requestBuilder = new StringBuilder();
            requestBuilder.append("POST / HTTP/1.1\r\n");
            requestBuilder.append("Host: ").append(host).append("\r\n");
            requestBuilder.append("Content-Type: application/x-amz-json-1.1\r\n");
            requestBuilder.append("X-Amz-Target: AWSCognitoIdentityService.GetOpenIdTokenForDeveloperIdentity\r\n");
            requestBuilder.append("Content-Length: ").append(requestBody.length()).append("\r\n");
            requestBuilder.append("\r\n");
            requestBuilder.append(requestBody);
            
            ByteArray requestBytes = ByteArray.byteArray(requestBuilder.toString().getBytes(StandardCharsets.UTF_8));
            HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
            HttpResponse response = montoyaApi.http().sendRequest(request).response();
            
            return new TestResult(
                response.statusCode() == 200,
                response.statusCode(),
                formatResponse(request, response),
                response.bodyToString(),
                formatRequest(request),
                formatResponseOnly(response),
                request,
                response
            );
        } catch (Exception e) {
            return new TestResult(false, 0, "Error: " + e.getMessage(), null, 
                "Error: " + e.getMessage(), null, null, null);
        }
    }
    
    /**
     * Extract credentials from GetCredentialsForIdentity response
     */
    public Map<String, String> extractCredentials(String responseBody) {
        Map<String, String> credentials = new HashMap<>();
        
        if (responseBody == null) {
            return credentials;
        }
        
        // Simple JSON parsing for credentials
        // Look for AccessKeyId, SecretKey, SessionToken
        java.util.regex.Pattern accessKeyPattern = java.util.regex.Pattern.compile(
            "\"AccessKeyId\"\\s*:\\s*\"([^\"]+)\"", java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Pattern secretKeyPattern = java.util.regex.Pattern.compile(
            "\"SecretKey\"\\s*:\\s*\"([^\"]+)\"", java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Pattern sessionTokenPattern = java.util.regex.Pattern.compile(
            "\"SessionToken\"\\s*:\\s*\"([^\"]+)\"", java.util.regex.Pattern.CASE_INSENSITIVE);
        
        java.util.regex.Matcher matcher = accessKeyPattern.matcher(responseBody);
        if (matcher.find()) {
            credentials.put("AccessKeyId", matcher.group(1));
        }
        
        matcher = secretKeyPattern.matcher(responseBody);
        if (matcher.find()) {
            credentials.put("SecretKey", matcher.group(1));
        }
        
        matcher = sessionTokenPattern.matcher(responseBody);
        if (matcher.find()) {
            credentials.put("SessionToken", matcher.group(1));
        }
        
        return credentials;
    }
    
    /**
     * Extract IdentityId from GetId response
     */
    public String extractIdentityId(String responseBody) {
        if (responseBody == null) {
            return null;
        }
        
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
            "\"IdentityId\"\\s*:\\s*\"([^\"]+)\"", java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher matcher = pattern.matcher(responseBody);
        
        if (matcher.find()) {
            return matcher.group(1);
        }
        
        return null;
    }
    
    private String escapeJson(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }
    
    private String formatResponse(HttpRequest request, HttpResponse response) {
        return formatRequest(request) + "\n" + formatResponseOnly(response);
    }
    
    public String formatRequest(HttpRequest request) {
        StringBuilder sb = new StringBuilder();
        sb.append("Request URL: ").append(request.url()).append("\n\n");
        sb.append("Request Headers:\n");
        for (burp.api.montoya.http.message.HttpHeader header : request.headers()) {
            sb.append("  ").append(header.name()).append(": ");
            String value = header.value();
            // Mask sensitive headers
            if (header.name().equalsIgnoreCase("Authorization") || 
                header.name().equalsIgnoreCase("X-Amz-Security-Token")) {
                if (value.length() > 20) {
                    value = value.substring(0, 20) + "...";
                }
            }
            sb.append(value).append("\n");
        }
        sb.append("\nRequest Body:\n");
        if (request.body().length() > 0) {
            String body = request.bodyToString();
            // Try to format JSON
            try {
                body = formatJson(body);
            } catch (Exception e) {
                // If formatting fails, use as-is
            }
            sb.append(body).append("\n");
        }
        return sb.toString();
    }
    
    public String formatResponseOnly(HttpResponse response) {
        StringBuilder sb = new StringBuilder();
        sb.append("Response Status: ").append(response.statusCode())
          .append(" ").append(response.reasonPhrase()).append("\n\n");
        sb.append("Response Headers:\n");
        for (burp.api.montoya.http.message.HttpHeader header : response.headers()) {
            sb.append("  ").append(header.name()).append(": ")
              .append(header.value()).append("\n");
        }
        sb.append("\nResponse Body:\n");
        if (response.body().length() > 0) {
            String body = response.bodyToString();
            // Try to format JSON
            try {
                body = formatJson(body);
            } catch (Exception e) {
                // If formatting fails, use as-is
            }
            sb.append(body);
        }
        return sb.toString();
    }
    
    private String formatJson(String json) {
        // Simple JSON formatting (indentation)
        StringBuilder formatted = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        
        for (char c : json.toCharArray()) {
            if (c == '"' && (formatted.length() == 0 || formatted.charAt(formatted.length() - 1) != '\\')) {
                inString = !inString;
                formatted.append(c);
            } else if (!inString) {
                if (c == '{' || c == '[') {
                    formatted.append(c).append("\n");
                    indent++;
                    formatted.append("  ".repeat(indent));
                } else if (c == '}' || c == ']') {
                    formatted.append("\n");
                    indent--;
                    formatted.append("  ".repeat(indent));
                    formatted.append(c);
                } else if (c == ',') {
                    formatted.append(c).append("\n");
                    formatted.append("  ".repeat(indent));
                } else if (c == ':') {
                    formatted.append(c).append(" ");
                } else if (!Character.isWhitespace(c)) {
                    formatted.append(c);
                }
            } else {
                formatted.append(c);
            }
        }
        
        return formatted.toString();
    }
    
    /**
     * Test result container
     */
    public static class TestResult {
        public final boolean success;
        public final int statusCode;
        public final String fullResponse;
        public final String responseBody;
        public final String requestDetails;
        public final String responseDetails;
        public final HttpRequest request;
        public final HttpResponse response;
        
        public TestResult(boolean success, int statusCode, String fullResponse, String responseBody,
                         String requestDetails, String responseDetails, HttpRequest request, HttpResponse response) {
            this.success = success;
            this.statusCode = statusCode;
            this.fullResponse = fullResponse;
            this.responseBody = responseBody;
            this.requestDetails = requestDetails;
            this.responseDetails = responseDetails;
            this.request = request;
            this.response = response;
        }
    }
}

