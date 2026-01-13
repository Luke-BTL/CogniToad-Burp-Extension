# Release Notes - v1.1.0

## 🎉 New Release: JWT Decoder & Sign-Up Testing

This release introduces comprehensive JWT token decoding and AWS Cognito user sign-up testing capabilities, including Burp Collaborator integration for out-of-band testing.

---

## ✨ New Features

### 🔐 JWT Decoder & Sign-Up Tester

A new comprehensive interface for JWT token analysis and AWS Cognito user sign-up testing:

#### JWT Token Decoding
- **Token Decoding**: Decode JWT tokens (base64url) and display formatted JSON payload
- **Automatic Client ID Extraction**: Automatically extracts `client_id` or `clientId` from JWT payloads
- **Formatted Display**: Shows decoded payload in readable, indented JSON format
- **Easy Integration**: Paste JWT tokens directly from authentication responses

#### Sign-Up Testing
- **Custom Credentials**: Enter custom email/username and password for sign-up testing
  - Pre-populated email: `cog_test@example.com`
  - Default password: `SuperSecure-123` (visible plain text)
  - Fully editable fields for custom testing scenarios
- **Force Alias Creation**: Radio button option to enable/disable `ForceAliasCreation` parameter
  - Useful for testing alias creation behavior
  - Equivalent to AWS CLI: `aws cognito-idp sign-up --force-alias-creation`
- **Burp Collaborator Integration**: 
  - Generate real Burp Collaborator payloads that can callback to Burp
  - Automatically appends payload to email addresses
  - Smart email handling: replaces domain if `@` exists, otherwise appends
  - Check for Collaborator interactions to detect out-of-band callbacks
  - Useful for testing email verification flows and detecting SSRF vulnerabilities
  - All interactions are associated with the Collaborator client for easy tracking
- **OTP/Confirmation Code Request**: Request OTP codes after user creation using `ResendConfirmationCode` API
  - Tests the confirmation code delivery mechanism
  - Useful for testing verification workflows
- **Detailed Results**: View full request and response details for all operations
  - Includes request headers, body, response status, and response body
  - All requests appear in Burp's HTTP history for inspection

**Key Features:**
- Seamless integration with Burp Collaborator for out-of-band testing
- Automatic client ID extraction from JWT tokens
- Real-time interaction checking with Collaborator server
- Pre-populated fields for quick testing
- All requests appear in Burp's HTTP history for inspection and modification

---

## 🔧 Technical Improvements

### New API Methods
- **SignUp API**: Added `signUp()` method with support for:
  - Custom client ID, username, password, and region
  - Optional `ForceAliasCreation` parameter
  - Proper AWS Cognito API request formatting
- **ResendConfirmationCode API**: Added `resendConfirmationCode()` method for:
  - Requesting OTP/confirmation codes
  - Testing verification code delivery mechanisms

### Burp Collaborator Integration
- **Reflection-Based API Access**: Uses reflection to access Burp Collaborator API
  - Compatible with different Montoya API versions
  - Creates Collaborator client context for payload generation
  - Stores client context for interaction polling
- **Payload Generation**: Generates valid Collaborator payloads with server location
- **Interaction Polling**: Retrieves and displays Collaborator interactions
  - Shows interaction details including type, protocol, client info, and timestamps
  - Helps detect out-of-band vulnerabilities

### UI Enhancements
- **New Tab**: "JWT Decoder & Sign-Up Tester" added as fourth main tab
- **Split Panel Layout**: 
  - Top panel: JWT input and decoded payload display
  - Bottom panel: Sign-up configuration and results
- **Button Organization**: 
  - "Test Sign-Up" button is primary (larger, bold, first position)
  - Secondary buttons: Generate Collaborator Payload, Check Interactions, Request OTP
- **Pre-populated Fields**: Email field pre-filled with `cog_test@example.com` for quick testing

---

## 📋 Usage Examples

### Decoding JWT Tokens

1. **Navigate to Tester**: Open **CogniToad** tab > **JWT Decoder & Sign-Up Tester** sub-tab
2. **Paste JWT Token**: Copy a JWT token from an authentication response
3. **Decode**: Click "Decode JWT" button
4. **Extract Client ID**: The `client_id` is automatically extracted and populated in the Client ID field
5. **Review Payload**: View the decoded payload in formatted JSON

### Testing User Sign-Up

1. **Enter Credentials**: 
   - Email/Username: Use default `cog_test@example.com` or enter custom value
   - Password: Use default `SuperSecure-123` or enter custom value
2. **Configure Options**:
   - Select Force Alias Creation: Yes or No (default: No)
3. **Optional - Add Collaborator Payload**:
   - Click "Generate Collaborator Payload" to create a payload
   - Payload is automatically appended to the email field
4. **Test Sign-Up**: Click "Test Sign-Up" button
5. **Review Results**: Check the response in the "Sign-Up Result" area
6. **Request OTP**: After successful sign-up, click "Request OTP/Confirmation Code"
7. **Check Interactions**: Click "Check Collaborator Interactions" to see if any callbacks occurred

### Using Collaborator for Out-of-Band Testing

1. **Generate Payload**: Click "Generate Collaborator Payload" button
2. **Automatic Integration**: Payload is automatically appended to your email address
3. **Test Sign-Up**: Perform sign-up with Collaborator payload in email
4. **Monitor Interactions**: 
   - Click "Check Collaborator Interactions" periodically
   - Interactions will appear when AWS Cognito (or other services) make outbound requests
   - Useful for detecting:
     - Email verification callbacks
     - SSRF vulnerabilities
     - Out-of-band data exfiltration

---

## 🔄 Migration Notes

- **No Breaking Changes**: All existing functionality remains unchanged
- **New Tab Added**: New "JWT Decoder & Sign-Up Tester" tab added to interface
- **Backward Compatible**: Works with existing Burp Suite configurations
- **No New Dependencies**: Uses existing Burp Montoya API

---

## 🐛 Known Limitations

1. **Collaborator API**: Uses reflection to access Collaborator API, which may need adjustment for future Burp API versions
2. **JWT Validation**: Currently only decodes JWT payloads; signature verification not implemented
3. **OTP Delivery**: OTP codes are delivered via the configured delivery method (email/SMS) and cannot be intercepted in the extension

---

## 📚 Documentation

- Updated README with comprehensive JWT Decoder & Sign-Up Tester documentation
- Usage instructions for all new features
- Examples for common testing scenarios

---

## 🙏 Credits

This release adds powerful JWT analysis and sign-up testing capabilities, making it easier to test AWS Cognito user registration flows and detect vulnerabilities through out-of-band testing with Burp Collaborator.

---

## 📦 Installation

1. Download the JAR file from the [Releases](https://github.com/Luke-BTL/CogniToad-Burp-Extension/releases) page
2. Load in Burp Suite: **Extensions > Installed > Add**
3. The "CogniToad" tab will appear with the new "JWT Decoder & Sign-Up Tester" tab

---

## 🔗 Links

- **Repository**: https://github.com/Luke-BTL/CogniToad-Burp-Extension
- **Issues**: https://github.com/Luke-BTL/CogniToad-Burp-Extension/issues
- **Documentation**: See README.md for detailed usage instructions

---

**Release Date**: 2025-01-XX  
**Version**: 1.1.0  
**Compatibility**: Burp Suite Professional/Community (Montoya API 2025.5)

