package com.cognitoad;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * AWS Signature Version 4 signing utility.
 * Implements the AWS Signature Version 4 algorithm for authenticating AWS API requests.
 */
public class AWSSignatureV4 {
    
    private static final String ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String SERVICE = "sts"; // Can be overridden
    private static final String TERMINATOR = "aws4_request";
    
    /**
     * Sign an AWS API request using Signature Version 4
     * Returns both the authorization header and the x-amz-date value
     */
    public static class SigningResult {
        public final String authorization;
        public final String amzDate;
        
        public SigningResult(String authorization, String amzDate) {
            this.authorization = authorization;
            this.amzDate = amzDate;
        }
    }
    
    public static SigningResult signRequestWithDate(String method, String host, String path, String queryString,
                                                    Map<String, String> headers, String payload,
                                                    String accessKeyId, String secretAccessKey, String sessionToken,
                                                    String region, String service) {
        try {
            // Get current timestamp
            Date now = new Date();
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
            SimpleDateFormat timeFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
            timeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
            dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
            
            String amzDate = timeFormat.format(now);
            String dateStamp = dateFormat.format(now);
            
            // Prepare headers
            Map<String, String> signedHeaders = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            if (headers != null) {
                signedHeaders.putAll(headers);
            }
            
            // Add required headers
            if (!signedHeaders.containsKey("host")) {
                signedHeaders.put("host", host);
            }
            signedHeaders.put("x-amz-date", amzDate); // Always set/override
            if (sessionToken != null && !sessionToken.isEmpty()) {
                signedHeaders.put("x-amz-security-token", sessionToken);
            }
            
            // Create canonical request
            String canonicalRequest = createCanonicalRequest(method, path, queryString, signedHeaders, payload);
            
            // Create string to sign
            String credentialScope = dateStamp + "/" + region + "/" + service + "/" + TERMINATOR;
            String stringToSign = ALGORITHM + "\n" + amzDate + "\n" + credentialScope + "\n" + 
                sha256Hex(canonicalRequest);
            
            // Calculate signature
            byte[] kSecret = ("AWS4" + secretAccessKey).getBytes(StandardCharsets.UTF_8);
            byte[] kDate = hmacSha256(kSecret, dateStamp);
            byte[] kRegion = hmacSha256(kDate, region);
            byte[] kService = hmacSha256(kRegion, service);
            byte[] kSigning = hmacSha256(kService, TERMINATOR);
            byte[] signature = hmacSha256(kSigning, stringToSign);
            String signatureHex = bytesToHex(signature);
            
            // Build authorization header
            String authorization = ALGORITHM + " " +
                "Credential=" + accessKeyId + "/" + credentialScope + ", " +
                "SignedHeaders=" + getSignedHeaders(signedHeaders) + ", " +
                "Signature=" + signatureHex;
            
            return new SigningResult(authorization, amzDate);
        } catch (Exception e) {
            throw new RuntimeException("Error signing AWS request: " + e.getMessage(), e);
        }
    }
    
    /**
     * Sign an AWS API request using Signature Version 4
     */
    public static String signRequest(String method, String host, String path, String queryString,
                                     Map<String, String> headers, String payload,
                                     String accessKeyId, String secretAccessKey, String sessionToken,
                                     String region, String service) {
        return signRequestWithDate(method, host, path, queryString, headers, payload,
            accessKeyId, secretAccessKey, sessionToken, region, service).authorization;
    }
    
    private static String createCanonicalRequest(String method, String path, String queryString,
                                                 Map<String, String> headers, String payload) {
        StringBuilder sb = new StringBuilder();
        
        // Method
        sb.append(method).append("\n");
        
        // Canonical URI
        sb.append(path.isEmpty() ? "/" : path).append("\n");
        
        // Canonical query string - must be sorted and URL encoded
        if (queryString != null && !queryString.isEmpty()) {
            sb.append(normalizeQueryString(queryString));
        }
        sb.append("\n");
        
        // Canonical headers - must be sorted by name (TreeMap already sorted)
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String key = entry.getKey().toLowerCase();
            String value = entry.getValue().trim();
            // Replace multiple spaces with single space
            value = value.replaceAll("\\s+", " ");
            sb.append(key).append(":").append(value).append("\n");
        }
        sb.append("\n");
        
        // Signed headers
        sb.append(getSignedHeaders(headers)).append("\n");
        
        // Payload hash
        String payloadHash = sha256Hex(payload != null ? payload : "");
        sb.append(payloadHash);
        
        return sb.toString();
    }
    
    private static String normalizeQueryString(String queryString) {
        // Parse and sort query parameters
        String[] params = queryString.split("&");
        List<String> sortedParams = new ArrayList<>();
        for (String param : params) {
            sortedParams.add(param);
        }
        Collections.sort(sortedParams);
        return String.join("&", sortedParams);
    }
    
    private static String getSignedHeaders(Map<String, String> headers) {
        List<String> headerNames = new ArrayList<>();
        for (String name : headers.keySet()) {
            headerNames.add(name.toLowerCase());
        }
        Collections.sort(headerNames);
        return String.join(";", headerNames);
    }
    
    private static byte[] hmacSha256(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
            mac.init(secretKeySpec);
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Error computing HMAC-SHA256: " + e.getMessage(), e);
        }
    }
    
    private static String sha256Hex(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error computing SHA-256: " + e.getMessage(), e);
        }
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}

