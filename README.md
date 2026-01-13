<p align="center">
  <img src="assets/cognitoad.png" alt="Cognitoad mascot" width="300">
</p>
<p align="center">
A Burp Suite extension that provides a comprehensive GUI for making AWS Cognito API requests, testing user attribute updates, and detecting security vulnerabilities in AWS Cognito Identity Pools.
</p>
## Features

### Core Operations

- **Get User** - Retrieve user information from AWS Cognito using an access token
- **Update User Attributes** - Update user attributes through a dialog interface

### Passive Scanning

- **Identity Pool ID Detection** - Automatically detects exposed AWS Cognito Identity Pool IDs in JavaScript files and inline scripts
  - Pattern: `region:UUID` format (e.g., `us-east-1:12345678-1234-1234-1234-123456789abc`)
  - Raises "Low" severity issues in Burp's issue findings
  - Highlights detected entries in the proxy history with orange color
- **Access Token Detection** - Automatically detects exposed access tokens in JSON request/response bodies
  - Detects `accessToken` and `access_token` fields
  - Raises "High" severity issues for tokens in responses, "Information" severity for tokens in requests
  - Highlights requests with yellow and responses with red color in proxy history

### Region Brute Forcing

- **Automatic Region Discovery** - Option to brute force all AWS regions until a successful response is found
- Supports all major AWS regions (29 regions including US, EU, APAC, etc.)
- Automatically stops when a successful response (HTTP 200) is received

### Update Attributes Repeater

A dedicated repeater-style interface for testing user attribute updates with two modes:

#### Manual Request Mode
- Edit JSON-formatted user attributes directly
- Send requests with keyboard shortcuts (Ctrl+Enter or Ctrl+Alt+Space)
- View responses in real-time

#### Brute Force Attributes Mode
- Test multiple attribute key-value combinations automatically
- Enter keys (attribute names) and values in separate lists (one per line)
- All combinations of keys × values are tested (e.g., 3 keys × 2 values = 6 combinations)
- View results in a table with status, key, value, and status code
- Click any result to view the full request and response
- Helps identify which attribute combinations are accepted or rejected

### Identity Pool Tester

A comprehensive security testing interface for AWS Cognito Identity Pools with the following tests:

- **Test Unauthenticated Access** - Attempts to obtain credentials without authentication
  - Tests `GetId` and `GetCredentialsForIdentity` APIs
  - If credentials are returned, indicates a critical vulnerability
  - Displays obtained credentials in copy-paste friendly format for terminal use
- **Test Get Caller Identity** - Tests STS `GetCallerIdentity` using obtained credentials
  - Verifies if temporary credentials can be used to identify the caller
  - Displays full request and response details
- **Enumerate AWS Services** - Tests access to various AWS services using temporary credentials
  - Tests S3 (`ListBuckets`), DynamoDB (`ListTables`), and Lambda (`ListFunctions`)
  - Flags successful access as critical vulnerabilities
  - Provides AWS CLI commands for manual testing
- **Detect Overprivileged Roles** - Placeholder for analyzing IAM role policies
  - Intended to detect wildcard actions (e.g., `s3:*`, `dynamodb:*`)
  - Manual review of IAM role policies recommended
- **Test Developer Identity Abuse** - Tests `GetOpenIdTokenForDeveloperIdentity` with arbitrary Logins
  - Detects if Identity Pool accepts arbitrary logins without validation
  - Indicates critical vulnerability if token is returned

**Features:**
- Auto-detects region from Identity Pool ID format (e.g., `eu-west-2:xxxxx` → `eu-west-2`)
- Displays detailed request and response information for each test
- Export credentials in terminal-friendly format (`export AWS_ACCESS_KEY_ID=...`)
- All tests use AWS Signature Version 4 signing for proper authentication

### Context Menu Integration

- **Access Token Extraction** - Right-click on HTTP requests/responses in Burp Suite to extract access tokens
  - Automatically extracts tokens from JSON response bodies (`accessToken`, `access_token`, `token`)
  - Falls back to `Authorization: Bearer` headers
  - Option to send extracted token directly to CogniToad extension
- **User Attributes Extraction** - Right-click on HTTP responses to extract user attributes
  - Supports AWS Cognito `UserAttributes` format
  - Also extracts key-value pairs from generic JSON responses
  - Automatically populates the repeater with extracted attributes
- **Identity Pool ID Extraction** - Right-click on HTTP responses containing Identity Pool IDs
  - Automatically detects Identity Pool IDs in JavaScript and inline scripts
  - Option to send detected Identity Pool ID directly to the Identity Pool Tester tab
  - Auto-populates the Identity Pool ID field and detects the region
  - If multiple IDs are found, provides a submenu to select which one to send

## How It Works

CogniToad integrates with Burp Suite's Montoya API to provide a seamless interface for AWS Cognito API interactions:

1. **AWS Signature Version 4 Signing** - All requests are properly signed using AWS Signature Version 4 for authentication
   - Used for all AWS service calls (Cognito, STS, S3, DynamoDB, Lambda)
   - Implements proper canonical request formatting and signature calculation
2. **HTTP Integration** - All requests are sent through Burp's HTTP API, appearing in HTTP history for inspection and modification
3. **Background Threading** - Operations run in background threads to maintain UI responsiveness
4. **Passive Scanning** - Automatically scans HTTP responses for security issues:
   - Scans JavaScript files and inline scripts for Identity Pool IDs
   - Scans JSON request/response bodies for access tokens
   - Creates audit issues in Burp's issue findings
   - Highlights vulnerable entries in proxy history
5. **Request Construction** - The extension constructs properly formatted AWS Cognito API requests:
   - `GetUser` requests to `AWSCognitoIdentityProviderService.GetUser`
   - `UpdateUserAttributes` requests to `AWSCognitoIdentityProviderService.UpdateUserAttributes`
   - `GetId` and `GetCredentialsForIdentity` for Identity Pool testing
   - `GetCallerIdentity` for STS testing
   - Service enumeration calls (S3, DynamoDB, Lambda)
6. **Response Parsing** - Responses are parsed and displayed with full request/response details including status codes and body content

## Installation

1. Load the extension JAR file in Burp Suite: **Extensions > Installed > Add > Select the JAR file**
2. The "CogniToad" tab will appear in Burp Suite
3. For quick reloading during development: Ctrl/⌘ + click the Loaded checkbox

## Usage

### Basic Operations

1. Open the **CogniToad** tab in Burp Suite
2. Enter your AWS Cognito access token in the "Access Token" field
3. Select the AWS region from the dropdown (default: `eu-west-2`)
4. Optionally enable "Brute force all regions" to automatically try all regions until successful
5. Click on the desired operation:
   - **Get User** - Retrieves and displays user information
   - **Update User Attributes** - Opens a dialog to update user attributes (JSON format)

### Using the Repeater

1. Navigate to the **Update Attributes Repeater** tab
2. Choose between **Manual Request** or **Brute Force Attributes** sub-tabs

#### Manual Request
- Edit the JSON in the request area (default example provided)
- Click "Send Request" or use Ctrl+Enter / Ctrl+Alt+Space shortcuts
- View the response in the output area below

#### Brute Force Attributes
- Enter attribute names (keys) in the left panel, one per line
- Enter values in the right panel, one per line
- Click "Start Brute Force" to test all combinations
- Review results in the table, clicking any row to see full request/response details

### Using the Identity Pool Tester

1. Navigate to the **CogniToad** tab > **Identity Pool Tester** sub-tab
2. Enter an Identity Pool ID (format: `region:UUID`, e.g., `us-east-1:12345678-1234-1234-1234-123456789abc`)
   - The region will be automatically detected from the Pool ID format
   - You can manually change the region if needed
3. Select the appropriate AWS region from the dropdown
4. Click on any of the security test buttons:
   - **Test Unauthenticated Access** - Tests if credentials can be obtained without authentication
   - **Test Get Caller Identity** - Tests STS GetCallerIdentity with obtained credentials
   - **Enumerate STS Temporary Credentials** - Tests access to S3, DynamoDB, and Lambda services
   - **Detect Overprivileged Roles** - Placeholder for IAM policy analysis
   - **Test Developer Identity Abuse** - Tests for arbitrary login acceptance
   - **Run All Tests** - Executes all tests sequentially
5. Review the results in the "Test Results Summary" area
6. View detailed request and response information in the "Request Details" and "Response Details" areas
7. If credentials are obtained, copy the export commands to your terminal for manual testing

**Note:** The automated service enumeration tests may fail due to AWS Signature Version 4 signing requirements. The extension provides AWS CLI commands that you can use for manual testing with the obtained credentials.

### Using Context Menus

The extension adds context menu items that allow you to quickly extract and send data from HTTP requests/responses directly to CogniToad.

#### Sending Access Token to the Extension

1. Navigate to **Proxy > HTTP history** (or **HTTP History** tab, or **Repeater**)
2. Find the HTTP request or response that contains an access token (typically a response from an authentication endpoint)
3. Right-click on the request/response entry in the list
4. Select **Send access token to CogniToad extension** from the context menu
5. The access token will be automatically extracted and populated in the "Access Token" field of the CogniToad tab
6. Open the **CogniToad** tab to verify the token has been set

**Note:** The extension automatically detects access tokens in:
- JSON response bodies (looks for `accessToken`, `access_token`, or `token` fields)
- `Authorization: Bearer` headers in requests or responses

#### Sending User Attributes to the Extension

1. Navigate to **Proxy > HTTP history** (or **HTTP History** tab)
2. Find an HTTP response that contains user attributes (typically a response from a user information endpoint)
3. Right-click on the response entry in the list
4. Select **Send user attributes to CogniToad extension** from the context menu
5. The user attributes will be automatically extracted and populated in the repeater
6. Navigate to the **CogniToad** tab > **Update Attributes Repeater** tab to see the extracted attributes

**Note:** The extension automatically extracts attributes from:
- AWS Cognito `UserAttributes` format (arrays of `Name`/`Value` pairs)
- Generic JSON key-value pairs (excluding token/metadata fields)

#### Sending Identity Pool ID to the Extension

1. Navigate to **Proxy > HTTP history** (or **HTTP History** tab)
2. Find an HTTP response that contains an Identity Pool ID (typically in JavaScript files or inline scripts)
   - Entries with detected Pool IDs are highlighted in orange in the proxy history
3. Right-click on the response entry in the list
4. Select **Send Identity Pool ID to CogniToad** from the context menu
   - If multiple Pool IDs are found, a submenu will appear with each ID listed
5. The Identity Pool ID will be automatically extracted and populated in the Identity Pool Tester tab
6. The region will be automatically detected from the Pool ID format
7. Navigate to the **CogniToad** tab > **Identity Pool Tester** sub-tab to see the populated fields

## Passive Scanning

The extension includes passive scanners that automatically detect security issues:

### Identity Pool ID Detection

- **Trigger:** Automatically scans HTTP responses during passive scanning
- **Detection:** Looks for Identity Pool IDs in JavaScript files and inline scripts
- **Pattern:** Matches `region:UUID` format (e.g., `us-east-1:12345678-1234-1234-1234-123456789abc`)
- **Issue Severity:** Low
- **Visual Indicator:** Entries in proxy history are highlighted in orange with a note

### Access Token Detection

- **Trigger:** Automatically scans HTTP requests and responses during passive scanning
- **Detection:** Looks for `accessToken` and `access_token` fields in JSON bodies
- **Issue Severity:** 
  - High (for tokens in responses)
  - Information (for tokens in requests)
- **Visual Indicator:** 
  - Requests with tokens: Yellow highlight
  - Responses with tokens: Red highlight

**Note:** To view issues found by passive scanners, navigate to **Scanner > Issue definitions** or run an active/passive scan on your target.

## Notes

- All HTTP requests are sent through Burp's HTTP API, so they appear in Burp's HTTP history and can be intercepted/modified
- Operations are executed in background threads to maintain UI responsiveness
- The extension requires valid AWS Cognito access tokens to function (for core operations)
- Region brute forcing tests all regions sequentially until a successful response (HTTP 200) is received
- Passive scanners automatically run during Burp's passive scanning phase
- Identity Pool testing requires the Identity Pool ID to be in the format `region:UUID`
- AWS Signature Version 4 signing is implemented for all AWS service calls
- Some automated tests may require manual verification using AWS CLI commands provided by the extension
