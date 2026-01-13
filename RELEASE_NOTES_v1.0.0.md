# Release Notes - v1.0.0

## 🎉 Major Release: Identity Pool Testing & Passive Scanning

This release introduces comprehensive security testing capabilities for AWS Cognito Identity Pools, passive scanning for exposed credentials, and enhanced context menu integration.

---

## ✨ New Features

### 🔍 Passive Scanning

#### Identity Pool ID Detection
- **Automatic Detection**: Scans HTTP responses for exposed AWS Cognito Identity Pool IDs
- **Pattern Matching**: Detects Pool IDs in JavaScript files and inline scripts using pattern `region:UUID`
- **Issue Reporting**: Creates "Low" severity audit issues in Burp's issue findings
- **Visual Highlighting**: Highlights detected entries in proxy history with orange color and descriptive notes
- **Examples**: Detects patterns like `us-east-1:12345678-1234-1234-1234-123456789abc`

#### Access Token Detection
- **Automatic Detection**: Scans HTTP requests and responses for exposed access tokens
- **JSON Body Scanning**: Detects `accessToken` and `access_token` fields in JSON bodies
- **Severity-Based Reporting**:
  - **High** severity for tokens found in responses (critical exposure)
  - **Information** severity for tokens found in requests
- **Visual Highlighting**:
  - Yellow highlight for requests containing tokens
  - Red highlight for responses containing tokens

### 🛡️ Identity Pool Tester

A comprehensive security testing interface for AWS Cognito Identity Pools with the following capabilities:

#### Test Unauthenticated Access
- Tests `GetId` API without authentication
- Tests `GetCredentialsForIdentity` API without authentication
- Identifies critical vulnerabilities when credentials are returned unauthenticated
- Displays obtained credentials in terminal-friendly format:
  ```bash
  export AWS_ACCESS_KEY_ID="..."
  export AWS_SECRET_ACCESS_KEY="..."
  export AWS_SESSION_TOKEN="..."
  ```

#### Test Get Caller Identity
- Tests STS `GetCallerIdentity` using obtained temporary credentials
- Verifies if credentials can be used to identify the caller
- Displays full request and response details for analysis

#### Enumerate AWS Services
- Tests access to multiple AWS services using temporary credentials:
  - **S3**: `ListBuckets` operation
  - **DynamoDB**: `ListTables` operation
  - **Lambda**: `ListFunctions` operation
- Flags successful access as critical vulnerabilities
- Provides AWS CLI commands for manual verification when automated tests require additional signing

#### Detect Overprivileged Roles
- Placeholder for IAM role policy analysis
- Intended to detect wildcard actions (e.g., `s3:*`, `dynamodb:*`)
- Manual review of IAM role policies recommended

#### Test Developer Identity Abuse
- Tests `GetOpenIdTokenForDeveloperIdentity` with arbitrary `Logins` parameter
- Detects if Identity Pool accepts arbitrary logins without validation
- Identifies critical vulnerability if token is returned

#### Key Features
- **Auto-Region Detection**: Automatically detects and sets AWS region from Identity Pool ID format
  - Example: `eu-west-2:xxxxx` → automatically sets region to `eu-west-2`
- **Detailed Request/Response Viewing**: Separate panels for viewing full request and response details
- **Batch Testing**: "Run All Tests" button to execute all security tests sequentially
- **Credential Export**: Copy-paste friendly credential export for terminal use

### 🔗 Enhanced Context Menu Integration

#### Identity Pool ID Extraction
- **Right-Click Integration**: Right-click on HTTP responses in proxy history to extract Identity Pool IDs
- **Automatic Detection**: Automatically detects Pool IDs in JavaScript and inline scripts
- **Auto-Population**: Sends detected Pool ID directly to Identity Pool Tester tab
- **Auto-Region Detection**: Automatically detects and sets region from Pool ID format
- **Multiple ID Support**: If multiple IDs are found, provides submenu to select which one to send

---

## 🔧 Technical Improvements

### AWS Signature Version 4 Implementation
- **Full Signing Support**: Complete implementation of AWS Signature Version 4 signing algorithm
- **Service Support**: Proper signing for all AWS services:
  - AWS Cognito Identity
  - AWS STS (Security Token Service)
  - Amazon S3
  - Amazon DynamoDB
  - AWS Lambda
- **Canonical Request Formatting**: Proper canonical request construction with sorted headers and query strings
- **Timestamp Handling**: Automatic `x-amz-date` header generation and inclusion

### Code Architecture
- **Modular Design**: New classes for better code organization:
  - `CognitoIdentityPoolIdScanner` - Passive scanner for Pool IDs
  - `CognitoIdentityPoolIdProxyHandler` - Proxy highlighting for Pool IDs
  - `AccessTokenScanner` - Passive scanner for access tokens
  - `AccessTokenProxyHandler` - Proxy highlighting for access tokens
  - `IdentityPoolTestClient` - Client for Identity Pool API calls
  - `IdentityPoolTestPanel` - UI for Identity Pool testing
  - `IdentityPoolIdContextMenuProvider` - Context menu integration
  - `AWSSignatureV4` - AWS Signature Version 4 signing utility

### UI Enhancements
- **Tabbed Interface**: Identity Pool Tester integrated as a sub-tab within CogniToad
- **Split Panels**: Separate panels for request and response viewing
- **Real-Time Updates**: Background threading for non-blocking UI operations
- **Visual Feedback**: Color-coded highlighting in proxy history

---

## 📋 Usage Examples

### Using Passive Scanning

1. **Automatic Detection**: Passive scanners run automatically during Burp's passive scanning phase
2. **View Issues**: Navigate to **Scanner > Issue definitions** to view detected issues
3. **Visual Indicators**: Check proxy history for highlighted entries:
   - Orange highlight = Identity Pool ID detected
   - Yellow highlight = Access token in request
   - Red highlight = Access token in response

### Using Identity Pool Tester

1. **Navigate to Tester**: Open **CogniToad** tab > **Identity Pool Tester** sub-tab
2. **Enter Pool ID**: Enter Identity Pool ID (format: `region:UUID`)
   - Region is automatically detected
3. **Run Tests**: Click any test button or use "Run All Tests"
4. **Review Results**: Check results summary and detailed request/response panels
5. **Export Credentials**: Copy export commands to terminal for manual testing

### Using Context Menu

1. **Find Detection**: Look for highlighted entries in proxy history
2. **Right-Click**: Right-click on the entry
3. **Select Option**: Choose from context menu:
   - "Send Identity Pool ID to CogniToad"
   - "Send access token to CogniToad extension"
   - "Send user attributes to CogniToad extension"
4. **Auto-Population**: Fields are automatically populated in the appropriate tab

---

## 🐛 Known Limitations

1. **Service Enumeration**: Some automated service enumeration tests may fail due to AWS Signature Version 4 signing complexity. The extension provides AWS CLI commands for manual testing.
2. **Overprivileged Role Detection**: Currently a placeholder. Manual review of IAM role policies is recommended.
3. **Region Detection**: Auto-detection works for standard AWS regions. Custom regions may require manual selection.

---

## 🔄 Migration Notes

- **No Breaking Changes**: All existing functionality remains unchanged
- **New Dependencies**: No new external dependencies required
- **Backward Compatible**: Works with existing Burp Suite configurations

---

## 📚 Documentation

- Updated README with comprehensive feature documentation
- Usage instructions for all new features
- Examples and screenshots (refer to README)

---

## 🙏 Credits

This release includes significant contributions to AWS Cognito security testing capabilities, making it easier to identify and test vulnerabilities in Identity Pool configurations.

---

## 📦 Installation

1. Download the JAR file from the [Releases](https://github.com/Luke-BTL/CogniToad-Burp-Extension/releases) page
2. Load in Burp Suite: **Extensions > Installed > Add**
3. The "CogniToad" tab will appear with all new features

---

## 🔗 Links

- **Repository**: https://github.com/Luke-BTL/CogniToad-Burp-Extension
- **Issues**: https://github.com/Luke-BTL/CogniToad-Burp-Extension/issues
- **Documentation**: See README.md for detailed usage instructions

---

**Release Date**: 2025-01-XX  
**Version**: 1.0.0  
**Compatibility**: Burp Suite Professional/Community (Montoya API 2025.5)

