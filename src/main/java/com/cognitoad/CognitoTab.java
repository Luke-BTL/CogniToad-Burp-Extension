package com.cognitoad;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

public class CognitoTab {
    private final MontoyaApi montoyaApi;
    private final JPanel mainPanel;
    private final JTextField accessTokenField;
    private final JComboBox<String> regionComboBox;
    private final JCheckBox bruteForceRegionsCheckbox;
    private final JTextArea resultArea;
    private JTextArea repeaterRequestArea;
    private JTextArea repeaterResponseArea;
    private JTextArea bruteForceKeysArea;
    private JTextArea bruteForceValuesArea;
    private JTable bruteForceResultsTable;
    private DefaultTableModel bruteForceTableModel;
    private JTextArea bruteForceRequestArea;
    private JTextArea bruteForceResponseArea;
    private java.util.List<BruteForceResult> bruteForceResults;
    private final CognitoClient cognitoClient;
    private volatile boolean isRunning = false;
    private volatile boolean isBruteForcing = false;
    
    private static final String[] AWS_REGIONS = {
        "us-east-1",      // US East (N. Virginia)
        "us-east-2",      // US East (Ohio)
        "us-west-1",      // US West (N. California)
        "us-west-2",      // US West (Oregon)
        "af-south-1",     // Africa (Cape Town)
        "ap-east-1",      // Asia Pacific (Hong Kong)
        "ap-south-1",     // Asia Pacific (Mumbai)
        "ap-south-2",     // Asia Pacific (Hyderabad)
        "ap-southeast-1", // Asia Pacific (Singapore)
        "ap-southeast-2", // Asia Pacific (Sydney)
        "ap-southeast-3", // Asia Pacific (Jakarta)
        "ap-southeast-4", // Asia Pacific (Melbourne)
        "ap-northeast-1", // Asia Pacific (Tokyo)
        "ap-northeast-2", // Asia Pacific (Seoul)
        "ap-northeast-3", // Asia Pacific (Osaka)
        "ca-central-1",   // Canada (Central)
        "ca-west-1",      // Canada (West)
        "eu-central-1",   // Europe (Frankfurt)
        "eu-central-2",   // Europe (Zurich)
        "eu-west-1",      // Europe (Ireland)
        "eu-west-2",      // Europe (London)
        "eu-west-3",      // Europe (Paris)
        "eu-south-1",     // Europe (Milan)
        "eu-south-2",     // Europe (Spain)
        "eu-north-1",     // Europe (Stockholm)
        "il-central-1",   // Israel (Tel Aviv)
        "me-central-1",   // Middle East (UAE)
        "me-south-1",     // Middle East (Bahrain)
        "sa-east-1"       // South America (São Paulo)
    };

    public CognitoTab(MontoyaApi montoyaApi) {
        this.montoyaApi = montoyaApi;
        this.cognitoClient = new CognitoClient(montoyaApi);
        
        mainPanel = new JPanel(new BorderLayout());
        
        // Create input panel
        JPanel inputPanel = new JPanel(new GridBagLayout());
        inputPanel.setBorder(new TitledBorder("Configuration"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Access Token field
        gbc.gridx = 0;
        gbc.gridy = 0;
        inputPanel.add(new JLabel("Access Token:"), gbc);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        accessTokenField = new JTextField(40);
        inputPanel.add(accessTokenField, gbc);
        
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
        regionComboBox.setSelectedItem("eu-west-2");
        inputPanel.add(regionComboBox, gbc);
        
        // Brute force regions checkbox
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        bruteForceRegionsCheckbox = new JCheckBox("Brute force all regions (try each region until successful)");
        inputPanel.add(bruteForceRegionsCheckbox, gbc);
        
        // Operations panel
        JPanel operationsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        operationsPanel.setBorder(new TitledBorder("Operations"));
        
        JButton getUserButton = new JButton("Get User");
        getUserButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                executeGetUser();
            }
        });
        
        JButton updateAttributesButton = new JButton("Update User Attributes");
        updateAttributesButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showUpdateAttributesDialog();
            }
        });
        
        operationsPanel.add(getUserButton);
        operationsPanel.add(updateAttributesButton);
        
        // Result area
        JPanel resultPanel = new JPanel(new BorderLayout());
        resultPanel.setBorder(new TitledBorder("Response"));
        resultArea = new JTextArea(15, 60);
        resultArea.setEditable(false);
        resultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(resultArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        resultPanel.add(scrollPane, BorderLayout.CENTER);
        
        // Combine panels for main operations
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(inputPanel, BorderLayout.NORTH);
        topPanel.add(operationsPanel, BorderLayout.SOUTH);
        
        // Create tabbed pane for different views
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Tab 1: Operations (current functionality)
        JPanel operationsTab = new JPanel(new BorderLayout());
        operationsTab.add(topPanel, BorderLayout.NORTH);
        operationsTab.add(resultPanel, BorderLayout.CENTER);
        tabbedPane.addTab("Operations", operationsTab);
        
        // Tab 2: Repeater for Update User Attributes
        JPanel repeaterTab = createRepeaterPanel();
        tabbedPane.addTab("Update Attributes Repeater", repeaterTab);
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    private JPanel createRepeaterPanel() {
        JPanel repeaterPanel = new JPanel(new BorderLayout());
        
        // Create a tabbed pane for manual request and brute-force
        JTabbedPane repeaterTabs = new JTabbedPane();
        
        // Tab 1: Manual Request
        JPanel manualRequestPanel = createManualRequestPanel();
        repeaterTabs.addTab("Manual Request", manualRequestPanel);
        
        // Tab 2: Brute Force Attributes
        JPanel bruteForcePanel = createBruteForcePanel();
        repeaterTabs.addTab("Brute Force Attributes", bruteForcePanel);
        
        // Output panel (shared) - only for Manual Request
        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(new TitledBorder("Output"));
        
        repeaterResponseArea = new JTextArea(5, 60);
        repeaterResponseArea.setEditable(false);
        repeaterResponseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane responseScroll = new JScrollPane(repeaterResponseArea);
        responseScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        responseScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        outputPanel.add(responseScroll, BorderLayout.CENTER);
        
        // Split pane for tabs/output
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, repeaterTabs, outputPanel);
        splitPane.setResizeWeight(0.85);
        splitPane.setDividerLocation(600);
        
        repeaterPanel.add(splitPane, BorderLayout.CENTER);
        
        return repeaterPanel;
    }
    
    private JPanel createManualRequestPanel() {
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(new TitledBorder("Request - User Attributes (JSON)"));
        
        repeaterRequestArea = new JTextArea(12, 60);
        repeaterRequestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        repeaterRequestArea.setText("{\n  \"email\": \"user@example.com\",\n  \"name\": \"John Doe\"\n}");
        JScrollPane requestScroll = new JScrollPane(repeaterRequestArea);
        requestScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        requestScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        requestPanel.add(requestScroll, BorderLayout.CENTER);
        
        // Send button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton sendButton = new JButton("Send Request");
        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                executeRepeaterRequest();
            }
        });
        buttonPanel.add(sendButton);
        JLabel shortcutLabel = new JLabel("(Ctrl+Enter or Ctrl+Alt+Space)");
        shortcutLabel.setForeground(Color.GRAY);
        shortcutLabel.setFont(shortcutLabel.getFont().deriveFont(Font.PLAIN, shortcutLabel.getFont().getSize() - 1));
        buttonPanel.add(shortcutLabel);
        requestPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        // Add keyboard shortcuts for sending request
        AbstractAction sendAction = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                executeRepeaterRequest();
            }
        };
        
        // Ctrl+Enter shortcut
        KeyStroke ctrlEnter = KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_DOWN_MASK);
        repeaterRequestArea.getInputMap(JComponent.WHEN_FOCUSED).put(ctrlEnter, "sendRepeaterRequest");
        repeaterRequestArea.getActionMap().put("sendRepeaterRequest", sendAction);
        
        // Ctrl+Alt+Space shortcut
        KeyStroke ctrlAltSpace = KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, KeyEvent.CTRL_DOWN_MASK | KeyEvent.ALT_DOWN_MASK);
        repeaterRequestArea.getInputMap(JComponent.WHEN_FOCUSED).put(ctrlAltSpace, "sendRepeaterRequestAlt");
        repeaterRequestArea.getActionMap().put("sendRepeaterRequestAlt", sendAction);
        
        return requestPanel;
    }
    
    private JPanel createBruteForcePanel() {
        JPanel bruteForcePanel = new JPanel(new BorderLayout());
        
        // Instructions
        JPanel instructionPanel = new JPanel(new BorderLayout());
        JLabel instructionLabel = new JLabel(
            "Enter keys (attribute names) and values in separate lists (one per line).<br>" +
            "All combinations of keys x values will be tested. Example: 3 keys x 2 values = 6 combinations."
        );
        instructionLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        instructionPanel.add(instructionLabel, BorderLayout.NORTH);
        
        // Split pane for keys and values
        JSplitPane inputSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        inputSplitPane.setResizeWeight(0.5);
        
        // Keys panel
        JPanel keysPanel = new JPanel(new BorderLayout());
        keysPanel.setBorder(new TitledBorder("Keys (Attribute Names)"));
        bruteForceKeysArea = new JTextArea(15, 30);
        bruteForceKeysArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        bruteForceKeysArea.setText("email\nname\nphone\ncustom_attribute");
        JScrollPane keysScroll = new JScrollPane(bruteForceKeysArea);
        keysScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        keysScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        keysPanel.add(keysScroll, BorderLayout.CENTER);
        
        // Values panel
        JPanel valuesPanel = new JPanel(new BorderLayout());
        valuesPanel.setBorder(new TitledBorder("Values"));
        bruteForceValuesArea = new JTextArea(15, 30);
        bruteForceValuesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        bruteForceValuesArea.setText("test@example.com\nadmin@example.com");
        JScrollPane valuesScroll = new JScrollPane(bruteForceValuesArea);
        valuesScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        valuesScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        valuesPanel.add(valuesScroll, BorderLayout.CENTER);
        
        inputSplitPane.setLeftComponent(keysPanel);
        inputSplitPane.setRightComponent(valuesPanel);
        inputSplitPane.setDividerLocation(300);
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton bruteForceButton = new JButton("Start Brute Force");
        bruteForceButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                executeBruteForceAttributes();
            }
        });
        buttonPanel.add(bruteForceButton);
        
        // Results table and request/response view
        JSplitPane resultsSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        resultsSplitPane.setResizeWeight(0.4);
        
        // Results table
        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(new TitledBorder("Results"));
        String[] columnNames = {"#", "Status", "Key", "Value", "Status Code"};
        bruteForceTableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        bruteForceResultsTable = new JTable(bruteForceTableModel);
        bruteForceResultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        bruteForceResultsTable.setRowSelectionAllowed(true);
        bruteForceResultsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        bruteForceResultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = bruteForceResultsTable.getSelectedRow();
                if (selectedRow >= 0 && bruteForceResults != null && selectedRow < bruteForceResults.size()) {
                    BruteForceResult result = bruteForceResults.get(selectedRow);
                    bruteForceRequestArea.setText(result.request);
                    bruteForceResponseArea.setText(result.response);
                }
            }
        });
        JScrollPane tableScroll = new JScrollPane(bruteForceResultsTable);
        tableScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        tableScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        tablePanel.add(tableScroll, BorderLayout.CENTER);
        
        // Request/Response view
        JSplitPane requestResponseSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        requestResponseSplit.setResizeWeight(0.5);
        
        JPanel requestViewPanel = new JPanel(new BorderLayout());
        requestViewPanel.setBorder(new TitledBorder("Request"));
        bruteForceRequestArea = new JTextArea(10, 50);
        bruteForceRequestArea.setEditable(false);
        bruteForceRequestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane requestViewScroll = new JScrollPane(bruteForceRequestArea);
        requestViewScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        requestViewScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        requestViewPanel.add(requestViewScroll, BorderLayout.CENTER);
        
        JPanel responseViewPanel = new JPanel(new BorderLayout());
        responseViewPanel.setBorder(new TitledBorder("Response"));
        bruteForceResponseArea = new JTextArea(10, 50);
        bruteForceResponseArea.setEditable(false);
        bruteForceResponseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane responseViewScroll = new JScrollPane(bruteForceResponseArea);
        responseViewScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        responseViewScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        responseViewPanel.add(responseViewScroll, BorderLayout.CENTER);
        
        requestResponseSplit.setTopComponent(requestViewPanel);
        requestResponseSplit.setBottomComponent(responseViewPanel);
        requestResponseSplit.setDividerLocation(300);
        
        resultsSplitPane.setLeftComponent(tablePanel);
        resultsSplitPane.setRightComponent(requestResponseSplit);
        resultsSplitPane.setDividerLocation(400);
        
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.4);
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.add(instructionPanel, BorderLayout.NORTH);
        inputPanel.add(inputSplitPane, BorderLayout.CENTER);
        inputPanel.add(buttonPanel, BorderLayout.SOUTH);
        mainSplit.setTopComponent(inputPanel);
        mainSplit.setBottomComponent(resultsSplitPane);
        mainSplit.setDividerLocation(300);
        
        bruteForcePanel.add(mainSplit, BorderLayout.CENTER);
        
        bruteForceResults = new java.util.ArrayList<>();
        
        return bruteForcePanel;
    }
    
    private static class BruteForceResult {
        String key;
        String value;
        boolean success;
        String statusCode;
        String request;
        String response;
        
        BruteForceResult(String key, String value, boolean success, String statusCode, String request, String response) {
            this.key = key;
            this.value = value;
            this.success = success;
            this.statusCode = statusCode;
            this.request = request;
            this.response = response;
        }
    }

    private void executeRepeaterRequest() {
        if (isRunning) {
            montoyaApi.logging().logToError("Operation already in progress");
            return;
        }
        
        String accessToken = accessTokenField.getText().trim();
        String region = (String) regionComboBox.getSelectedItem();
        String attributesJson = repeaterRequestArea.getText().trim();
        
        if (accessToken.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter an access token", 
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (attributesJson.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter user attributes JSON", 
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        isRunning = true;
        repeaterResponseArea.setText("Sending request...\n");
        
        // Execute in background thread
        new Thread(() -> {
            try {
                if (bruteForceRegionsCheckbox.isSelected()) {
                    // Try all regions until we find a successful one
                    String result = bruteForceUpdateUserAttributes(accessToken, attributesJson);
                    SwingUtilities.invokeLater(() -> {
                        repeaterResponseArea.setText(result);
                        isRunning = false;
                    });
                } else {
                    // Use selected region
                    String result = cognitoClient.updateUserAttributes(accessToken, region, attributesJson);
                    SwingUtilities.invokeLater(() -> {
                        repeaterResponseArea.setText(result);
                        isRunning = false;
                    });
                }
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    repeaterResponseArea.setText("Error: " + e.getMessage() + "\n\nStack trace:\n" + 
                        getStackTrace(e));
                    isRunning = false;
                });
                montoyaApi.logging().logToError("Error executing Repeater request: " + e.getMessage());
            }
        }).start();
    }
    
    private void executeBruteForceAttributes() {
        if (isBruteForcing || isRunning) {
            montoyaApi.logging().logToError("Operation already in progress");
            return;
        }
        
        String accessToken = accessTokenField.getText().trim();
        String region = (String) regionComboBox.getSelectedItem();
        
        if (accessToken.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter an access token",
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        String keysText = bruteForceKeysArea.getText().trim();
        String valuesText = bruteForceValuesArea.getText().trim();
        
        if (keysText.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter at least one key",
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (valuesText.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter at least one value",
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // Parse keys and values
        java.util.List<String> keys = parseList(keysText);
        java.util.List<String> values = parseList(valuesText);
        
        if (keys.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "No valid keys found",
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (values.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "No valid values found",
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // Generate all combinations
        java.util.List<java.util.Map.Entry<String, String>> combinations = generateCombinations(keys, values);
        
        isBruteForcing = true;
        
        // Clear previous results
        SwingUtilities.invokeLater(() -> {
            bruteForceTableModel.setRowCount(0);
            bruteForceResults.clear();
            bruteForceRequestArea.setText("");
            bruteForceResponseArea.setText("");
        });
        
        // Execute in background thread
        new Thread(() -> {
            try {
                String result = bruteForceAttributeTesting(accessToken, region, combinations);
                SwingUtilities.invokeLater(() -> {
                    repeaterResponseArea.setText(result);
                    isBruteForcing = false;
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    repeaterResponseArea.setText("Error: " + e.getMessage() + "\n\nStack trace:\n" +
                        getStackTrace(e));
                    isBruteForcing = false;
                });
                montoyaApi.logging().logToError("Error executing brute force: " + e.getMessage());
            }
        }).start();
    }
    
    private java.util.List<String> parseList(String input) {
        java.util.List<String> list = new java.util.ArrayList<>();
        String[] lines = input.split("\n");
        
        for (String line : lines) {
            line = line.trim();
            if (!line.isEmpty()) {
                list.add(line);
            }
        }
        
        return list;
    }
    
    private java.util.List<java.util.Map.Entry<String, String>> generateCombinations(
            java.util.List<String> keys, java.util.List<String> values) {
        java.util.List<java.util.Map.Entry<String, String>> combinations = new java.util.ArrayList<>();
        
        for (String key : keys) {
            for (String value : values) {
                combinations.add(new java.util.AbstractMap.SimpleEntry<>(key, value));
            }
        }
        
        return combinations;
    }
    
    private String bruteForceAttributeTesting(String accessToken, String region, 
            java.util.List<java.util.Map.Entry<String, String>> attributes) {
        bruteForceResults.clear();
        
        for (int i = 0; i < attributes.size(); i++) {
            java.util.Map.Entry<String, String> attr = attributes.get(i);
            String key = attr.getKey();
            String value = attr.getValue();
            
            String requestJson = "{\"" + escapeJson(key) + "\":\"" + escapeJson(value) + "\"}";
            String fullResponse = "";
            String statusCode = "";
            boolean success = false;
            
            try {
                // Try with selected region first, then brute force if needed
                if (bruteForceRegionsCheckbox.isSelected()) {
                    fullResponse = bruteForceUpdateUserAttributes(accessToken, requestJson);
                } else {
                    fullResponse = cognitoClient.updateUserAttributes(accessToken, region, requestJson);
                }
                
                // Extract status code
                if (fullResponse != null) {
                    int statusIndex = fullResponse.indexOf("Response Status: ");
                    if (statusIndex >= 0) {
                        int endIndex = fullResponse.indexOf("\n", statusIndex);
                        if (endIndex > statusIndex) {
                            String statusLine = fullResponse.substring(statusIndex + "Response Status: ".length(), endIndex).trim();
                            statusCode = statusLine.split(" ")[0];
                            success = statusCode.equals("200");
                        }
                    }
                }
            } catch (Exception e) {
                fullResponse = "Error: " + e.getMessage();
                statusCode = "Error";
                success = false;
            }
            
            final int rowIndex = i;
            final String finalStatusCode = statusCode;
            final boolean finalSuccess = success;
            final String finalResponse = fullResponse != null ? fullResponse : "";
            
            BruteForceResult result = new BruteForceResult(key, value, finalSuccess, finalStatusCode, requestJson, finalResponse);
            bruteForceResults.add(result);
            
            // Add row to table
            SwingUtilities.invokeLater(() -> {
                String statusText = finalSuccess ? "SUCCESS" : "FAILED";
                bruteForceTableModel.addRow(new Object[]{
                    rowIndex + 1,
                    statusText,
                    key,
                    value.length() > 50 ? value.substring(0, 50) + "..." : value,
                    finalStatusCode
                });
            });
        }
        
        return "Brute force completed. " + bruteForceResults.size() + " combinations tested.";
    }
    
    private String escapeJson(String str) {
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    private void executeGetUser() {
        if (isRunning) {
            montoyaApi.logging().logToError("Operation already in progress");
            return;
        }
        
        String accessToken = accessTokenField.getText().trim();
        String region = (String) regionComboBox.getSelectedItem();
        
        if (accessToken.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter an access token", 
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (region.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter a region", 
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        isRunning = true;
        
        // Execute in background thread
        new Thread(() -> {
            try {
                if (bruteForceRegionsCheckbox.isSelected()) {
                    // Try all regions until we find a successful one
                    String result = bruteForceGetUser(accessToken);
                    SwingUtilities.invokeLater(() -> {
                        resultArea.setText(result);
                        // Parse and populate repeater with user attributes
                        populateRepeaterFromGetUserResponse(result);
                        isRunning = false;
                    });
                } else {
                    // Use selected region
                    resultArea.setText("Executing GetUser operation...\n");
                    String result = cognitoClient.getUser(accessToken, region);
                    SwingUtilities.invokeLater(() -> {
                        resultArea.setText(result);
                        // Parse and populate repeater with user attributes
                        populateRepeaterFromGetUserResponse(result);
                        isRunning = false;
                    });
                }
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    resultArea.setText("Error: " + e.getMessage() + "\n\nStack trace:\n" + 
                        getStackTrace(e));
                    isRunning = false;
                });
                montoyaApi.logging().logToError("Error executing GetUser: " + e.getMessage());
            }
        }).start();
    }

    private void showUpdateAttributesDialog() {
        JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainPanel), 
            "Update User Attributes", true);
        dialog.setLayout(new BorderLayout());
        
        JPanel dialogPanel = new JPanel(new BorderLayout());
        dialogPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        JTextArea attributesArea = new JTextArea(10, 40);
        attributesArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        attributesArea.setText("{\n  \"email\": \"user@example.com\",\n  \"name\": \"John Doe\"\n}");
        JScrollPane attributesScroll = new JScrollPane(attributesArea);
        
        JLabel instructionLabel = new JLabel(
            "<html>Enter attributes as JSON object (one attribute per line):<br>" +
            "Example: {\"email\": \"user@example.com\", \"name\": \"John Doe\"}</html>");
        instructionLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        
        dialogPanel.add(instructionLabel, BorderLayout.NORTH);
        dialogPanel.add(attributesScroll, BorderLayout.CENTER);
        
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton updateButton = new JButton("Update");
        JButton cancelButton = new JButton("Cancel");
        
        updateButton.addActionListener(e -> {
            dialog.dispose();
            executeUpdateUserAttributes(attributesArea.getText());
        });
        
        cancelButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(updateButton);
        buttonPanel.add(cancelButton);
        dialogPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.add(dialogPanel);
        dialog.pack();
        dialog.setLocationRelativeTo(mainPanel);
        dialog.setVisible(true);
    }

    private void executeUpdateUserAttributes(String attributesJson) {
        if (isRunning) {
            montoyaApi.logging().logToError("Operation already in progress");
            return;
        }
        
        String accessToken = accessTokenField.getText().trim();
        String region = (String) regionComboBox.getSelectedItem();
        
        if (accessToken.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter an access token", 
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        isRunning = true;
        
        // Execute in background thread
        new Thread(() -> {
            try {
                if (bruteForceRegionsCheckbox.isSelected()) {
                    // Try all regions until we find a successful one
                    String result = bruteForceUpdateUserAttributes(accessToken, attributesJson);
                    SwingUtilities.invokeLater(() -> {
                        resultArea.setText(result);
                        isRunning = false;
                    });
                } else {
                    // Use selected region
                    resultArea.setText("Executing UpdateUserAttributes operation...\n");
                    String result = cognitoClient.updateUserAttributes(accessToken, region, attributesJson);
                    SwingUtilities.invokeLater(() -> {
                        resultArea.setText(result);
                        isRunning = false;
                    });
                }
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    resultArea.setText("Error: " + e.getMessage() + "\n\nStack trace:\n" + 
                        getStackTrace(e));
                    isRunning = false;
                });
                montoyaApi.logging().logToError("Error executing UpdateUserAttributes: " + e.getMessage());
            }
        }).start();
    }

    private String bruteForceGetUser(String accessToken) {
        StringBuilder progress = new StringBuilder();
        progress.append("Brute forcing all regions for GetUser operation...\n");
        for (int i = 0; i < 80; i++) {
            progress.append("=");
        }
        progress.append("\n\n");
        
        SwingUtilities.invokeLater(() -> {
            resultArea.setText(progress.toString());
        });
        
        for (String region : AWS_REGIONS) {
            try {
                String statusText = progress.toString() + "Trying region: " + region + "...\n";
                SwingUtilities.invokeLater(() -> {
                    resultArea.setText(statusText);
                });
                
                String response = cognitoClient.getUser(accessToken, region);
                
                // Check if the response indicates success (HTTP 200 status)
                if (response != null && response.contains("Response Status: 200")) {
                    StringBuilder success = new StringBuilder();
                    success.append(progress.toString());
                    success.append("SUCCESS! Found working region: ").append(region).append("\n\n");
                    success.append(response);
                    return success.toString();
                }
                
                progress.append("Region ").append(region).append(" failed (not HTTP 200)\n");
            } catch (Exception e) {
                progress.append("Region ").append(region).append(" failed: ").append(e.getMessage()).append("\n");
            }
        }
        
        StringBuilder finalResult = new StringBuilder();
        finalResult.append(progress.toString());
        finalResult.append("\n");
        for (int i = 0; i < 80; i++) {
            finalResult.append("=");
        }
        finalResult.append("\n");
        finalResult.append("All regions tried. None were successful.");
        return finalResult.toString();
    }

    private String bruteForceUpdateUserAttributes(String accessToken, String attributesJson) {
        StringBuilder progress = new StringBuilder();
        progress.append("Brute forcing all regions for UpdateUserAttributes operation...\n");
        for (int i = 0; i < 80; i++) {
            progress.append("=");
        }
        progress.append("\n\n");
        
        SwingUtilities.invokeLater(() -> {
            resultArea.setText(progress.toString());
        });
        
        for (String region : AWS_REGIONS) {
            try {
                String statusText = progress.toString() + "Trying region: " + region + "...\n";
                SwingUtilities.invokeLater(() -> {
                    resultArea.setText(statusText);
                });
                
                String response = cognitoClient.updateUserAttributes(accessToken, region, attributesJson);
                
                // Check if the response indicates success (HTTP 200 status)
                if (response != null && response.contains("Response Status: 200")) {
                    StringBuilder success = new StringBuilder();
                    success.append(progress.toString());
                    success.append("SUCCESS! Found working region: ").append(region).append("\n\n");
                    success.append(response);
                    return success.toString();
                }
                
                progress.append("Region ").append(region).append(" failed (not HTTP 200)\n");
            } catch (Exception e) {
                progress.append("Region ").append(region).append(" failed: ").append(e.getMessage()).append("\n");
            }
        }
        
        StringBuilder finalResult = new StringBuilder();
        finalResult.append(progress.toString());
        finalResult.append("\n");
        for (int i = 0; i < 80; i++) {
            finalResult.append("=");
        }
        finalResult.append("\n");
        finalResult.append("All regions tried. None were successful.");
        return finalResult.toString();
    }

    private String getStackTrace(Exception e) {
        java.io.StringWriter sw = new java.io.StringWriter();
        java.io.PrintWriter pw = new java.io.PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }

    public void cleanup() {
        isRunning = false;
        isBruteForcing = false;
    }

    public Component getUiComponent() {
        return mainPanel;
    }

    public void setAccessToken(String token) {
        SwingUtilities.invokeLater(() -> {
            accessTokenField.setText(token);
        });
    }
    
    public void populateUserAttributes(java.util.List<String> keys, java.util.List<String> values) {
        SwingUtilities.invokeLater(() -> {
            // Populate manual request field (as JSON object)
            if (repeaterRequestArea != null && !keys.isEmpty()) {
                StringBuilder jsonBuilder = new StringBuilder();
                jsonBuilder.append("{\n");
                for (int i = 0; i < keys.size(); i++) {
                    if (i > 0) {
                        jsonBuilder.append(",\n");
                    }
                    String key = keys.get(i);
                    String value = i < values.size() ? values.get(i) : "";
                    jsonBuilder.append("  \"").append(escapeJsonValue(key)).append("\": \"")
                              .append(escapeJsonValue(value)).append("\"");
                }
                jsonBuilder.append("\n}");
                repeaterRequestArea.setText(jsonBuilder.toString());
            }
            
            // Populate brute force fields (keys and values as separate lists)
            if (bruteForceKeysArea != null && !keys.isEmpty()) {
                StringBuilder keysBuilder = new StringBuilder();
                for (int i = 0; i < keys.size(); i++) {
                    if (i > 0) {
                        keysBuilder.append("\n");
                    }
                    keysBuilder.append(keys.get(i));
                }
                bruteForceKeysArea.setText(keysBuilder.toString());
            }
            
            if (bruteForceValuesArea != null && !values.isEmpty()) {
                StringBuilder valuesBuilder = new StringBuilder();
                for (int i = 0; i < values.size(); i++) {
                    if (i > 0) {
                        valuesBuilder.append("\n");
                    }
                    valuesBuilder.append(values.get(i));
                }
                bruteForceValuesArea.setText(valuesBuilder.toString());
            }
            
            montoyaApi.logging().logToOutput("Populated user attributes: " + keys.size() + " keys, " + values.size() + " values");
        });
    }

    private void populateRepeaterFromGetUserResponse(String responseText) {
        try {
            if (repeaterRequestArea == null) {
                return; // Repeater not initialized yet
            }
            
            // Extract the response body JSON from the formatted response
            int bodyStart = responseText.indexOf("Response Body:\n");
            if (bodyStart == -1) {
                montoyaApi.logging().logToOutput("Response Body not found in GetUser response");
                return; // No response body found
            }
            
            bodyStart += "Response Body:\n".length();
            String responseBody = responseText.substring(bodyStart).trim();
            
            montoyaApi.logging().logToOutput("Extracted response body, length: " + responseBody.length());
            
            // Parse the JSON response to extract UserAttributes
            String attributesJson = extractAttributesFromGetUserResponse(responseBody);
            if (attributesJson != null && !attributesJson.isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    repeaterRequestArea.setText(attributesJson);
                });
                montoyaApi.logging().logToOutput("Successfully populated repeater with attributes");
            } else {
                montoyaApi.logging().logToOutput("Failed to extract attributes from response body");
            }
        } catch (Exception e) {
            montoyaApi.logging().logToOutput("Error populating repeater from GetUser response: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String extractAttributesFromGetUserResponse(String responseBody) {
        try {
            // AWS Cognito GetUser response format:
            // {
            //   "Username": "...",
            //   "UserAttributes": [
            //     {"Name": "email", "Value": "user@example.com"},
            //     {"Name": "name", "Value": "John Doe"},
            //     ...
            //   ]
            // }
            
            montoyaApi.logging().logToOutput("Attempting to extract attributes from response body (first 200 chars): " + 
                (responseBody.length() > 200 ? responseBody.substring(0, 200) : responseBody));
            
            // Find UserAttributes array using regex
            // Pattern matches: "UserAttributes": [ ... ]
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                "\"UserAttributes\"\\s*:\\s*\\[\\s*((?:\\{[^}]*\\}[,\\s]*)*)\\]",
                java.util.regex.Pattern.DOTALL
            );
            java.util.regex.Matcher matcher = pattern.matcher(responseBody);
            
            if (!matcher.find()) {
                montoyaApi.logging().logToOutput("UserAttributes pattern not found in response");
                return null;
            }
            
            String attributesArrayContent = matcher.group(1);
            
            // Extract individual attribute objects: {"Name": "...", "Value": "..."}
            java.util.regex.Pattern attrPattern = java.util.regex.Pattern.compile(
                "\\{\\s*\"Name\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"Value\"\\s*:\\s*\"([^\"]*)\"\\s*\\}"
            );
            java.util.regex.Matcher attrMatcher = attrPattern.matcher(attributesArrayContent);
            
            StringBuilder result = new StringBuilder();
            result.append("{\n");
            boolean first = true;
            
            while (attrMatcher.find()) {
                if (!first) {
                    result.append(",\n");
                }
                String name = attrMatcher.group(1);
                String value = attrMatcher.group(2);
                result.append("  \"").append(name).append("\": \"")
                      .append(value).append("\"");
                first = false;
            }
            
            if (!first) {
                result.append("\n}");
                montoyaApi.logging().logToOutput("Successfully extracted " + (first ? 0 : result.toString().split(",").length) + " attributes");
                return result.toString();
            } else {
                montoyaApi.logging().logToOutput("No attributes found in UserAttributes array");
            }
        } catch (Exception e) {
            montoyaApi.logging().logToError("Error extracting attributes: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    private String escapeJsonValue(String value) {
        return value.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
    }
}

