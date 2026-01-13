package com.cognitoad;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Map;

/**
 * Panel for testing AWS Cognito Identity Pool security.
 * Integrated into the CogniToad tab.
 */
public class IdentityPoolTestPanel {
    private final MontoyaApi montoyaApi;
    private final JPanel panel;
    private final JTextField identityPoolIdField;
    private final JComboBox<String> regionComboBox;
    private final JTextArea resultsArea;
    private final JTextArea requestArea;
    private final JTextArea responseArea;
    private final IdentityPoolTestClient testClient;
    private volatile boolean isRunning = false;
    
    /**
     * Set the Identity Pool ID field and auto-detect region
     */
    public void setIdentityPoolId(String poolId) {
        SwingUtilities.invokeLater(() -> {
            identityPoolIdField.setText(poolId);
            detectRegionFromPoolId();
        });
    }
    
    private static final String[] AWS_REGIONS = {
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
        "ap-south-1", "ca-central-1", "sa-east-1"
    };
    
    public IdentityPoolTestPanel(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        this.testClient = new IdentityPoolTestClient(montoyaApi);
        
        panel = new JPanel(new BorderLayout());
        
        // Create input panel
        JPanel inputPanel = new JPanel(new GridBagLayout());
        inputPanel.setBorder(new TitledBorder("Configuration"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Identity Pool ID field
        gbc.gridx = 0;
        gbc.gridy = 0;
        inputPanel.add(new JLabel("Identity Pool ID:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        identityPoolIdField = new JTextField(50);
        // Add listener to auto-detect region from Identity Pool ID
        identityPoolIdField.addActionListener(e -> detectRegionFromPoolId());
        identityPoolIdField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                detectRegionFromPoolId();
            }
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                detectRegionFromPoolId();
            }
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                detectRegionFromPoolId();
            }
        });
        inputPanel.add(identityPoolIdField, gbc);
        
        // Region dropdown
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        inputPanel.add(new JLabel("Region:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        regionComboBox = new JComboBox<>(AWS_REGIONS);
        regionComboBox.setSelectedItem("us-east-1");
        inputPanel.add(regionComboBox, gbc);
        
        // Create test buttons panel
        JPanel testPanel = new JPanel(new GridBagLayout());
        testPanel.setBorder(new TitledBorder("Security Tests"));
        GridBagConstraints testGbc = new GridBagConstraints();
        testGbc.insets = new Insets(5, 5, 5, 5);
        testGbc.fill = GridBagConstraints.HORIZONTAL;
        testGbc.weightx = 1.0;
        
        // Test 1: Unauthenticated Access
        JButton testUnauthButton = new JButton("Test Unauthenticated Access");
        testUnauthButton.addActionListener(e -> testUnauthenticatedAccess());
        testGbc.gridx = 0;
        testGbc.gridy = 0;
        testPanel.add(testUnauthButton, testGbc);
        
        // Test 2: Get Caller Identity
        JButton testGetCallerIdButton = new JButton("Test Get Caller Identity");
        testGetCallerIdButton.addActionListener(e -> testGetCallerIdentity());
        testGbc.gridy = 1;
        testPanel.add(testGetCallerIdButton, testGbc);
        
        // Test 3: Enumerate STS Credentials
        JButton testSTSCredsButton = new JButton("Enumerate STS Temporary Credentials");
        testSTSCredsButton.addActionListener(e -> testSTSCredentials());
        testGbc.gridy = 2;
        testPanel.add(testSTSCredsButton, testGbc);
        
        // Test 4: Detect Overprivileged Roles
        JButton testPrivilegeButton = new JButton("Detect Overprivileged Roles");
        testPrivilegeButton.addActionListener(e -> testOverprivilegedRoles());
        testGbc.gridy = 3;
        testPanel.add(testPrivilegeButton, testGbc);
        
        // Test 5: Developer Identity Abuse
        JButton testDevIdentityButton = new JButton("Test Developer Identity Abuse");
        testDevIdentityButton.addActionListener(e -> testDeveloperIdentityAbuse());
        testGbc.gridy = 4;
        testPanel.add(testDevIdentityButton, testGbc);
        
        // Run All Tests button
        JButton runAllButton = new JButton("Run All Tests");
        runAllButton.addActionListener(e -> runAllTests());
        testGbc.gridy = 5;
        testPanel.add(runAllButton, testGbc);
        
        // Results area (summary)
        resultsArea = new JTextArea(8, 80);
        resultsArea.setEditable(false);
        resultsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane resultsScroll = new JScrollPane(resultsArea);
        resultsScroll.setBorder(new TitledBorder("Test Results Summary"));
        
        // Request area
        requestArea = new JTextArea(15, 80);
        requestArea.setEditable(false);
        requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane requestScroll = new JScrollPane(requestArea);
        requestScroll.setBorder(new TitledBorder("Request Details"));
        
        // Response area
        responseArea = new JTextArea(15, 80);
        responseArea.setEditable(false);
        responseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane responseScroll = new JScrollPane(responseArea);
        responseScroll.setBorder(new TitledBorder("Response Details"));
        
        // Create split panes
        JSplitPane requestResponseSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        requestResponseSplit.setLeftComponent(requestScroll);
        requestResponseSplit.setRightComponent(responseScroll);
        requestResponseSplit.setResizeWeight(0.5);
        requestResponseSplit.setDividerLocation(400);
        
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setTopComponent(resultsScroll);
        mainSplit.setBottomComponent(requestResponseSplit);
        mainSplit.setResizeWeight(0.3);
        mainSplit.setDividerLocation(200);
        
        // Layout
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(inputPanel, BorderLayout.NORTH);
        topPanel.add(testPanel, BorderLayout.CENTER);
        
        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(mainSplit, BorderLayout.CENTER);
    }
    
    public JPanel getPanel() {
        return panel;
    }
    
    /**
     * Automatically detect and set the region from the Identity Pool ID format (region:uuid)
     */
    private void detectRegionFromPoolId() {
        String poolId = identityPoolIdField.getText().trim();
        if (poolId.isEmpty()) {
            return;
        }
        
        // Identity Pool ID format: region:uuid
        // Example: eu-west-2:12345678-1234-1234-1234-123456789abc
        int colonIndex = poolId.indexOf(':');
        if (colonIndex > 0) {
            String detectedRegion = poolId.substring(0, colonIndex);
            
            // Check if the detected region is in our list of valid regions
            for (String region : AWS_REGIONS) {
                if (region.equals(detectedRegion)) {
                    // Set the region combo box to the detected region
                    regionComboBox.setSelectedItem(detectedRegion);
                    return;
                }
            }
        }
    }
    
    private void testUnauthenticatedAccess() {
        if (isRunning) {
            JOptionPane.showMessageDialog(panel, "A test is already running.");
            return;
        }
        
        String identityPoolId = identityPoolIdField.getText().trim();
        if (identityPoolId.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "Please enter an Identity Pool ID.");
            return;
        }
        
        String region = (String) regionComboBox.getSelectedItem();
        isRunning = true;
        resultsArea.setText("Testing unauthenticated access...\n\n");
        
        new Thread(() -> {
            try {
                StringBuilder results = new StringBuilder();
                results.append("=== Testing Unauthenticated Access ===\n\n");
                
                // Test GetId
                results.append("1. Testing GetId without authentication...\n");
                results.append("   Status: ");
                IdentityPoolTestClient.TestResult getIdResult = testClient.testGetIdUnauthenticated(identityPoolId, region);
                results.append(getIdResult.statusCode);
                if (getIdResult.success) {
                    results.append(" - SUCCESS (VULNERABLE!)\n");
                    String identityId = testClient.extractIdentityId(getIdResult.responseBody);
                    if (identityId != null) {
                        results.append("   IdentityId: ").append(identityId).append("\n");
                        
                        // Log issue
                        montoyaApi.logging().logToOutput("ISSUE [HIGH]: Unauthenticated Access to Cognito Identity Pool - IdentityId: " + identityId);
                    }
                } else {
                    results.append(" - FAILED (Secure)\n");
                }
                results.append("\n");
                
                // Update request and response areas
                SwingUtilities.invokeLater(() -> {
                    requestArea.setText(getIdResult.requestDetails != null ? getIdResult.requestDetails : "");
                    responseArea.setText(getIdResult.responseDetails != null ? getIdResult.responseDetails : "");
                });
                
                // Test GetCredentialsForIdentity if GetId succeeded
                if (getIdResult.success) {
                    String identityId = testClient.extractIdentityId(getIdResult.responseBody);
                    if (identityId != null) {
                        results.append("2. Testing GetCredentialsForIdentity without authentication...\n");
                        results.append("   Status: ");
                        IdentityPoolTestClient.TestResult getCredsResult = testClient.testGetCredentialsUnauthenticated(identityId, region);
                        results.append(getCredsResult.statusCode);
                        if (getCredsResult.success) {
                            results.append(" - SUCCESS (VULNERABLE!)\n");
                            
                            Map<String, String> credentials = testClient.extractCredentials(getCredsResult.responseBody);
                            if (!credentials.isEmpty()) {
                                results.append("   Credentials obtained!\n\n");
                                results.append("   Copy and paste these commands into your terminal:\n");
                                results.append("\n");
                                if (credentials.containsKey("AccessKeyId")) {
                                    results.append("export AWS_ACCESS_KEY_ID=\"").append(credentials.get("AccessKeyId")).append("\"\n");
                                }
                                if (credentials.containsKey("SecretKey")) {
                                    results.append("export AWS_SECRET_ACCESS_KEY=\"").append(credentials.get("SecretKey")).append("\"\n");
                                }
                                if (credentials.containsKey("SessionToken")) {
                                    results.append("export AWS_SESSION_TOKEN=\"").append(credentials.get("SessionToken")).append("\"\n");
                                }
                                results.append("\n");
                                
                                // Log issue
                                montoyaApi.logging().logToOutput("ISSUE [HIGH]: Unauthenticated Credential Access to Cognito Identity Pool");
                            }
                        } else {
                            results.append(" - FAILED (Secure)\n");
                        }
                        results.append("\n");
                        
                        // Update request and response areas
                        SwingUtilities.invokeLater(() -> {
                            requestArea.setText(getCredsResult.requestDetails != null ? getCredsResult.requestDetails : "");
                            responseArea.setText(getCredsResult.responseDetails != null ? getCredsResult.responseDetails : "");
                        });
                    }
                }
                
                SwingUtilities.invokeLater(() -> {
                    resultsArea.setText(results.toString());
                    isRunning = false;
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    resultsArea.setText("Error: " + e.getMessage() + "\n\n" + getStackTrace(e));
                    isRunning = false;
                });
            }
        }).start();
    }
    
    private void testGetCallerIdentity() {
        if (isRunning) {
            JOptionPane.showMessageDialog(panel, "A test is already running.");
            return;
        }
        
        String identityPoolId = identityPoolIdField.getText().trim();
        if (identityPoolId.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "Please enter an Identity Pool ID.");
            return;
        }
        
        String region = (String) regionComboBox.getSelectedItem();
        isRunning = true;
        resultsArea.setText("Testing Get Caller Identity...\n\n");
        
        new Thread(() -> {
            try {
                StringBuilder results = new StringBuilder();
                results.append("=== Testing Get Caller Identity ===\n\n");
                
                // First get credentials
                IdentityPoolTestClient.TestResult getIdResult = testClient.testGetIdUnauthenticated(identityPoolId, region);
                if (!getIdResult.success) {
                    results.append("Failed to obtain IdentityId. Cannot proceed with GetCallerIdentity test.\n");
                    SwingUtilities.invokeLater(() -> {
                        resultsArea.setText(results.toString());
                        isRunning = false;
                    });
                    return;
                }
                
                String identityId = testClient.extractIdentityId(getIdResult.responseBody);
                if (identityId == null) {
                    results.append("Failed to extract IdentityId from response.\n");
                    SwingUtilities.invokeLater(() -> {
                        resultsArea.setText(results.toString());
                        isRunning = false;
                    });
                    return;
                }
                
                IdentityPoolTestClient.TestResult getCredsResult = testClient.testGetCredentialsUnauthenticated(identityId, region);
                if (!getCredsResult.success) {
                    results.append("Failed to obtain credentials. Cannot proceed with GetCallerIdentity test.\n");
                    SwingUtilities.invokeLater(() -> {
                        resultsArea.setText(results.toString());
                        isRunning = false;
                    });
                    return;
                }
                
                Map<String, String> credentials = testClient.extractCredentials(getCredsResult.responseBody);
                if (credentials.isEmpty()) {
                    results.append("Failed to extract credentials from response.\n");
                    SwingUtilities.invokeLater(() -> {
                        resultsArea.setText(results.toString());
                        isRunning = false;
                    });
                    return;
                }
                
                results.append("Credentials obtained!\n\n");
                results.append("Testing STS GetCallerIdentity...\n");
                results.append("Status: ");
                IdentityPoolTestClient.TestResult stsResult = testClient.testSTSGetCallerIdentity(
                    credentials.get("AccessKeyId"),
                    credentials.get("SecretKey"),
                    credentials.get("SessionToken"),
                    region
                );
                results.append(stsResult.statusCode);
                if (stsResult.success) {
                    results.append(" - SUCCESS\n");
                    results.append("\nResponse:\n");
                    results.append(stsResult.responseBody != null ? stsResult.responseBody : "No response body");
                    montoyaApi.logging().logToOutput("ISSUE [HIGH]: Unauthenticated STS Access via Identity Pool");
                } else {
                    results.append(" - FAILED\n");
                }
                results.append("\n");
                
                // Update request and response areas
                SwingUtilities.invokeLater(() -> {
                    requestArea.setText(stsResult.requestDetails != null ? stsResult.requestDetails : "");
                    responseArea.setText(stsResult.responseDetails != null ? stsResult.responseDetails : "");
                });
                
                SwingUtilities.invokeLater(() -> {
                    resultsArea.setText(results.toString());
                    isRunning = false;
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    resultsArea.setText("Error: " + e.getMessage() + "\n\n" + getStackTrace(e));
                    isRunning = false;
                });
            }
        }).start();
    }
    
    private void testSTSCredentials() {
        if (isRunning) {
            JOptionPane.showMessageDialog(panel, "A test is already running.");
            return;
        }
        
        String identityPoolId = identityPoolIdField.getText().trim();
        if (identityPoolId.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "Please enter an Identity Pool ID.");
            return;
        }
        
        String region = (String) regionComboBox.getSelectedItem();
        isRunning = true;
        resultsArea.setText("Enumerating AWS services...\n\n");
        
        new Thread(() -> {
            try {
                StringBuilder results = new StringBuilder();
                results.append("=== Enumerating AWS Services ===\n\n");
                
                // First get credentials
                IdentityPoolTestClient.TestResult getIdResult = testClient.testGetIdUnauthenticated(identityPoolId, region);
                if (!getIdResult.success) {
                    results.append("Failed to obtain IdentityId. Cannot proceed with service enumeration.\n");
                    SwingUtilities.invokeLater(() -> {
                        resultsArea.setText(results.toString());
                        isRunning = false;
                    });
                    return;
                }
                
                String identityId = testClient.extractIdentityId(getIdResult.responseBody);
                if (identityId == null) {
                    results.append("Failed to extract IdentityId from response.\n");
                    SwingUtilities.invokeLater(() -> {
                        resultsArea.setText(results.toString());
                        isRunning = false;
                    });
                    return;
                }
                
                IdentityPoolTestClient.TestResult getCredsResult = testClient.testGetCredentialsUnauthenticated(identityId, region);
                if (!getCredsResult.success) {
                    results.append("Failed to obtain credentials. Cannot proceed with service enumeration.\n");
                    SwingUtilities.invokeLater(() -> {
                        resultsArea.setText(results.toString());
                        isRunning = false;
                    });
                    return;
                }
                
                Map<String, String> credentials = testClient.extractCredentials(getCredsResult.responseBody);
                if (credentials.isEmpty()) {
                    results.append("Failed to extract credentials from response.\n");
                    SwingUtilities.invokeLater(() -> {
                        resultsArea.setText(results.toString());
                        isRunning = false;
                    });
                    return;
                }
                
                results.append("Credentials obtained!\n\n");
                results.append("Copy and paste these commands into your terminal (optional - for CLI testing):\n");
                results.append("\n");
                if (credentials.containsKey("AccessKeyId")) {
                    results.append("export AWS_ACCESS_KEY_ID=\"").append(credentials.get("AccessKeyId")).append("\"\n");
                }
                if (credentials.containsKey("SecretKey")) {
                    results.append("export AWS_SECRET_ACCESS_KEY=\"").append(credentials.get("SecretKey")).append("\"\n");
                }
                if (credentials.containsKey("SessionToken")) {
                    results.append("export AWS_SESSION_TOKEN=\"").append(credentials.get("SessionToken")).append("\"\n");
                }
                results.append("\n");
                results.append("Testing access to AWS services with AWS Signature Version 4 signing...\n\n");
                
                // Test S3 ListBuckets
                results.append("1. Testing S3 ListBuckets...\n");
                results.append("   Status: ");
                IdentityPoolTestClient.TestResult s3Result = testClient.testS3ListBuckets(
                    credentials.get("AccessKeyId"),
                    credentials.get("SecretKey"),
                    credentials.get("SessionToken"),
                    region
                );
                results.append(s3Result.statusCode);
                if (s3Result.success) {
                    results.append(" - SUCCESS (CRITICAL!)\n");
                    montoyaApi.logging().logToOutput("ISSUE [HIGH]: Unauthenticated S3 Access via Identity Pool");
                } else {
                    results.append(" - FAILED\n");
                }
                results.append("\n");
                
                // Update request and response areas
                SwingUtilities.invokeLater(() -> {
                    requestArea.setText(s3Result.requestDetails != null ? s3Result.requestDetails : "");
                    responseArea.setText(s3Result.responseDetails != null ? s3Result.responseDetails : "");
                });
                
                // Test DynamoDB ListTables
                results.append("2. Testing DynamoDB ListTables...\n");
                results.append("   Status: ");
                IdentityPoolTestClient.TestResult ddbResult = testClient.testDynamoDBListTables(
                    credentials.get("AccessKeyId"),
                    credentials.get("SecretKey"),
                    credentials.get("SessionToken"),
                    region
                );
                results.append(ddbResult.statusCode);
                if (ddbResult.success) {
                    results.append(" - SUCCESS (CRITICAL!)\n");
                    montoyaApi.logging().logToOutput("ISSUE [HIGH]: Unauthenticated DynamoDB Access via Identity Pool");
                } else {
                    results.append(" - FAILED\n");
                }
                results.append("\n");
                
                // Update request and response areas
                SwingUtilities.invokeLater(() -> {
                    requestArea.setText(ddbResult.requestDetails != null ? ddbResult.requestDetails : "");
                    responseArea.setText(ddbResult.responseDetails != null ? ddbResult.responseDetails : "");
                });
                
                // Test Lambda ListFunctions
                results.append("3. Testing Lambda ListFunctions...\n");
                results.append("   Status: ");
                IdentityPoolTestClient.TestResult lambdaResult = testClient.testLambdaListFunctions(
                    credentials.get("AccessKeyId"),
                    credentials.get("SecretKey"),
                    credentials.get("SessionToken"),
                    region
                );
                results.append(lambdaResult.statusCode);
                if (lambdaResult.success) {
                    results.append(" - SUCCESS (CRITICAL!)\n");
                    montoyaApi.logging().logToOutput("ISSUE [HIGH]: Unauthenticated Lambda Access via Identity Pool");
                } else {
                    results.append(" - FAILED\n");
                }
                results.append("\n");
                
                // Update request and response areas
                SwingUtilities.invokeLater(() -> {
                    requestArea.setText(lambdaResult.requestDetails != null ? lambdaResult.requestDetails : "");
                    responseArea.setText(lambdaResult.responseDetails != null ? lambdaResult.responseDetails : "");
                });
                
                SwingUtilities.invokeLater(() -> {
                    resultsArea.setText(results.toString());
                    isRunning = false;
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    resultsArea.setText("Error: " + e.getMessage() + "\n\n" + getStackTrace(e));
                    isRunning = false;
                });
            }
        }).start();
    }
    
    private void testOverprivilegedRoles() {
        // This would analyze the IAM role policies
        // For now, we'll check if we can access multiple services
        resultsArea.setText("Overprivileged role detection requires analyzing IAM policies.\n" +
            "This feature would check for wildcard actions (e.g., s3:*, dynamodb:*) or\n" +
            "unscoped resource access. Manual review of IAM role policies is recommended.\n\n" +
            "If the previous tests showed access to multiple services, the role may be overprivileged.");
    }
    
    private void testDeveloperIdentityAbuse() {
        if (isRunning) {
            JOptionPane.showMessageDialog(panel, "A test is already running.");
            return;
        }
        
        String identityPoolId = identityPoolIdField.getText().trim();
        if (identityPoolId.isEmpty()) {
            JOptionPane.showMessageDialog(panel, "Please enter an Identity Pool ID.");
            return;
        }
        
        String region = (String) regionComboBox.getSelectedItem();
        isRunning = true;
        resultsArea.setText("Testing Developer Identity abuse...\n\n");
        
        new Thread(() -> {
            try {
                StringBuilder results = new StringBuilder();
                results.append("=== Testing Developer Identity Abuse ===\n\n");
                
                results.append("Testing GetOpenIdTokenForDeveloperIdentity with arbitrary Logins...\n");
                results.append("Status: ");
                IdentityPoolTestClient.TestResult result = testClient.testDeveloperIdentityAbuse(identityPoolId, region);
                results.append(result.statusCode);
                if (result.success) {
                    results.append(" - SUCCESS (VULNERABLE!)\n");
                    results.append("The Identity Pool accepts arbitrary Logins without validation.\n");
                    
                    montoyaApi.logging().logToOutput("ISSUE [HIGH]: Developer Identity Abuse in Cognito Identity Pool");
                } else {
                    results.append(" - FAILED (Secure)\n");
                }
                results.append("\n");
                
                // Update request and response areas
                SwingUtilities.invokeLater(() -> {
                    requestArea.setText(result.requestDetails != null ? result.requestDetails : "");
                    responseArea.setText(result.responseDetails != null ? result.responseDetails : "");
                });
                
                SwingUtilities.invokeLater(() -> {
                    resultsArea.setText(results.toString());
                    isRunning = false;
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    resultsArea.setText("Error: " + e.getMessage() + "\n\n" + getStackTrace(e));
                    isRunning = false;
                });
            }
        }).start();
    }
    
    private void runAllTests() {
        testUnauthenticatedAccess();
        // Note: Other tests depend on credentials, so they would need to be chained
        // For simplicity, running them sequentially
        try {
            Thread.sleep(2000);
            testGetCallerIdentity();
            Thread.sleep(2000);
            testSTSCredentials();
            Thread.sleep(2000);
            testDeveloperIdentityAbuse();
        } catch (InterruptedException e) {
            // Ignore
        }
    }
    
    private String getStackTrace(Exception e) {
        java.io.StringWriter sw = new java.io.StringWriter();
        java.io.PrintWriter pw = new java.io.PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }
}

