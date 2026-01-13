package com.cognitoad;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;

/**
 * Client for making AWS Cognito API requests.
 * 
 * Note: AWS Cognito API requires AWS Signature Version 4 signing for authentication.
 * This implementation uses the access token directly, but may require AWS credentials
 * and signature signing for actual API calls. The requests are sent through Burp's
 * HTTP API so they can be intercepted and modified if needed.
 */
public class CognitoClient {
    private final MontoyaApi montoyaApi;

    public CognitoClient(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
    }

    public String getUser(String accessToken, String region) throws Exception {
        String host = "cognito-idp." + region + ".amazonaws.com";
        
        // Create HTTP service
        HttpService httpService = HttpService.httpService(host, 443, true);
        
        // Build JSON request body
        String requestBody = "{\"AccessToken\":\"" + escapeJson(accessToken) + "\"}";
        
        // Build HTTP request
        StringBuilder requestBuilder = new StringBuilder();
        requestBuilder.append("POST / HTTP/1.1\r\n");
        requestBuilder.append("Host: ").append(host).append("\r\n");
        requestBuilder.append("Content-Type: application/x-amz-json-1.1\r\n");
        requestBuilder.append("X-Amz-Target: AWSCognitoIdentityProviderService.GetUser\r\n");
        requestBuilder.append("Authorization: Bearer ").append(accessToken).append("\r\n");
        requestBuilder.append("Content-Length: ").append(requestBody.length()).append("\r\n");
        requestBuilder.append("\r\n");
        requestBuilder.append(requestBody);
        
        ByteArray requestBytes = ByteArray.byteArray(requestBuilder.toString().getBytes(StandardCharsets.UTF_8));
        HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
        
        // Send request using Burp's HTTP API
        HttpResponse response = montoyaApi.http().sendRequest(request).response();
        
        // Format response
        return formatResponse(request, response);
    }

    public String updateUserAttributes(String accessToken, String region, String attributesJson) throws Exception {
        String host = "cognito-idp." + region + ".amazonaws.com";
        
        // Create HTTP service
        HttpService httpService = HttpService.httpService(host, 443, true);
        
        // Parse and format attributes
        String userAttributes = formatUserAttributesJson(attributesJson);
        
        // Build JSON request body
        String requestBody = "{\"AccessToken\":\"" + escapeJson(accessToken) + 
            "\",\"UserAttributes\":" + userAttributes + "}";
        
        // Build HTTP request
        StringBuilder requestBuilder = new StringBuilder();
        requestBuilder.append("POST / HTTP/1.1\r\n");
        requestBuilder.append("Host: ").append(host).append("\r\n");
        requestBuilder.append("Content-Type: application/x-amz-json-1.1\r\n");
        requestBuilder.append("X-Amz-Target: AWSCognitoIdentityProviderService.UpdateUserAttributes\r\n");
        requestBuilder.append("Authorization: Bearer ").append(accessToken).append("\r\n");
        requestBuilder.append("Content-Length: ").append(requestBody.length()).append("\r\n");
        requestBuilder.append("\r\n");
        requestBuilder.append(requestBody);
        
        ByteArray requestBytes = ByteArray.byteArray(requestBuilder.toString().getBytes(StandardCharsets.UTF_8));
        HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
        
        // Send request using Burp's HTTP API
        HttpResponse response = montoyaApi.http().sendRequest(request).response();
        
        // Format response
        return formatResponse(request, response);
    }

    public String signUp(String clientId, String username, String password, String region) throws Exception {
        return signUp(clientId, username, password, region, false);
    }
    
    public String signUp(String clientId, String username, String password, String region, boolean forceAliasCreation) throws Exception {
        String host = "cognito-idp." + region + ".amazonaws.com";
        
        // Create HTTP service
        HttpService httpService = HttpService.httpService(host, 443, true);
        
        // Build JSON request body
        StringBuilder requestBodyBuilder = new StringBuilder();
        requestBodyBuilder.append("{\"ClientId\":\"").append(escapeJson(clientId))
            .append("\",\"Username\":\"").append(escapeJson(username))
            .append("\",\"Password\":\"").append(escapeJson(password)).append("\"");
        
        // Add ForceAliasCreation if enabled
        if (forceAliasCreation) {
            requestBodyBuilder.append(",\"ForceAliasCreation\":true");
        }
        
        requestBodyBuilder.append("}");
        String requestBody = requestBodyBuilder.toString();
        
        // Build HTTP request
        StringBuilder requestBuilder = new StringBuilder();
        requestBuilder.append("POST / HTTP/1.1\r\n");
        requestBuilder.append("Host: ").append(host).append("\r\n");
        requestBuilder.append("Content-Type: application/x-amz-json-1.1\r\n");
        requestBuilder.append("X-Amz-Target: AWSCognitoIdentityProviderService.SignUp\r\n");
        requestBuilder.append("Content-Length: ").append(requestBody.length()).append("\r\n");
        requestBuilder.append("\r\n");
        requestBuilder.append(requestBody);
        
        ByteArray requestBytes = ByteArray.byteArray(requestBuilder.toString().getBytes(StandardCharsets.UTF_8));
        HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
        
        // Send request using Burp's HTTP API
        HttpResponse response = montoyaApi.http().sendRequest(request).response();
        
        // Format response
        return formatResponse(request, response);
    }

    public String resendConfirmationCode(String clientId, String username, String region) throws Exception {
        String host = "cognito-idp." + region + ".amazonaws.com";
        
        // Create HTTP service
        HttpService httpService = HttpService.httpService(host, 443, true);
        
        // Build JSON request body
        String requestBody = "{\"ClientId\":\"" + escapeJson(clientId) + 
            "\",\"Username\":\"" + escapeJson(username) + "\"}";
        
        // Build HTTP request
        StringBuilder requestBuilder = new StringBuilder();
        requestBuilder.append("POST / HTTP/1.1\r\n");
        requestBuilder.append("Host: ").append(host).append("\r\n");
        requestBuilder.append("Content-Type: application/x-amz-json-1.1\r\n");
        requestBuilder.append("X-Amz-Target: AWSCognitoIdentityProviderService.ResendConfirmationCode\r\n");
        requestBuilder.append("Content-Length: ").append(requestBody.length()).append("\r\n");
        requestBuilder.append("\r\n");
        requestBuilder.append(requestBody);
        
        ByteArray requestBytes = ByteArray.byteArray(requestBuilder.toString().getBytes(StandardCharsets.UTF_8));
        HttpRequest request = HttpRequest.httpRequest(httpService, requestBytes);
        
        // Send request using Burp's HTTP API
        HttpResponse response = montoyaApi.http().sendRequest(request).response();
        
        // Format response
        return formatResponse(request, response);
    }

    private String formatUserAttributesJson(String inputJson) {
        // Simple JSON parsing - convert object to array format
        // Input: {"email": "user@example.com", "name": "John Doe"}
        // Output: [{"Name":"email","Value":"user@example.com"},{"Name":"name","Value":"John Doe"}]
        
        try {
            // Remove outer braces and parse
            String cleaned = inputJson.trim();
            if (cleaned.startsWith("{")) {
                cleaned = cleaned.substring(1);
            }
            if (cleaned.endsWith("}")) {
                cleaned = cleaned.substring(0, cleaned.length() - 1);
            }
            
            StringBuilder result = new StringBuilder("[");
            String[] pairs = cleaned.split(",");
            boolean first = true;
            
            for (String pair : pairs) {
                String[] keyValue = pair.split(":", 2);
                if (keyValue.length == 2) {
                    String key = keyValue[0].trim().replace("\"", "");
                    String value = keyValue[1].trim().replace("\"", "");
                    
                    if (!first) {
                        result.append(",");
                    }
                    result.append("{\"Name\":\"").append(escapeJson(key))
                          .append("\",\"Value\":\"").append(escapeJson(value)).append("\"}");
                    first = false;
                }
            }
            
            result.append("]");
            return result.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse attributes JSON: " + e.getMessage(), e);
        }
    }

    private String escapeJson(String str) {
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    private String formatResponse(HttpRequest request, HttpResponse response) {
        StringBuilder sb = new StringBuilder();
        sb.append("Request URL: ").append(request.url()).append("\n\n");
        sb.append("Request Headers:\n");
        for (burp.api.montoya.http.message.HttpHeader header : request.headers()) {
            sb.append("  ").append(header.name()).append(": ");
            String value = header.value();
            // Mask sensitive headers
            if (header.name().equalsIgnoreCase("Authorization")) {
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
        
        sb.append("\n");
        for (int i = 0; i < 80; i++) {
            sb.append("=");
        }
        sb.append("\n\n");
        
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
}

