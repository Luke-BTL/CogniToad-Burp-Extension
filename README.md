# CogniToad - Burp Suite Extension

A Burp Suite extension that provides a comprehensive GUI for making AWS Cognito API requests and testing user attribute updates.

## Features

### Core Operations

- **Get User** - Retrieve user information from AWS Cognito using an access token
- **Update User Attributes** - Update user attributes through a dialog interface

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

### Context Menu Integration

- **Access Token Extraction** - Right-click on HTTP requests/responses in Burp Suite to extract access tokens
  - Automatically extracts tokens from JSON response bodies (`accessToken`, `access_token`, `token`)
  - Falls back to `Authorization: Bearer` headers
  - Option to send extracted token directly to CogniToad extension
- **User Attributes Extraction** - Right-click on HTTP responses to extract user attributes
  - Supports AWS Cognito `UserAttributes` format
  - Also extracts key-value pairs from generic JSON responses
  - Automatically populates the repeater with extracted attributes

## How It Works

CogniToad integrates with Burp Suite's Montoya API to provide a seamless interface for AWS Cognito API interactions:

1. **AWS Signature Version 4 Signing** - All requests are properly signed using AWS Signature Version 4 for authentication
2. **HTTP Integration** - All requests are sent through Burp's HTTP API, appearing in HTTP history for inspection and modification
3. **Background Threading** - Operations run in background threads to maintain UI responsiveness
4. **Request Construction** - The extension constructs properly formatted AWS Cognito API requests:
   - `GetUser` requests to `AWSCognitoIdentityProviderService.GetUser`
   - `UpdateUserAttributes` requests to `AWSCognitoIdentityProviderService.UpdateUserAttributes`
5. **Response Parsing** - Responses are parsed and displayed with full request/response details including status codes and body content

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

### Using Context Menus

1. In Burp Suite's HTTP History, Proxy, or Repeater, right-click on a request or response
2. Select from the context menu:
   - **Send access token to CogniToad extension** - Extracts and sends the token to the extension
   - **Send user attributes to CogniToad extension** - Extracts and populates the repeater with attributes

## Notes

- All HTTP requests are sent through Burp's HTTP API, so they appear in Burp's HTTP history and can be intercepted/modified
- Operations are executed in background threads to maintain UI responsiveness
- The extension requires valid AWS Cognito access tokens to function
- Region brute forcing tests all regions sequentially until a successful response (HTTP 200) is received
