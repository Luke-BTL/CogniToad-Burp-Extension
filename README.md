# CognitoToAd - Burp Suite Extension

A Burp Suite extension that provides a GUI for making AWS Cognito API requests.

## Features

- GUI interface for AWS Cognito operations
- Input fields for access token and AWS region
- Support for Cognito operations:
  - `get-user` - Retrieve user information
  - `update-user-attributes` - Update user attributes

## Building

```bash
./gradlew build    # Build and test the extension
./gradlew jar      # Create the extension JAR file
./gradlew clean    # Clean build artifacts
```

The built JAR file will be in `build/libs/` and can be loaded directly into Burp Suite.

## Installation

1. Build the JAR using `./gradlew jar`
2. In Burp Suite: Extensions > Installed > Add > Select the JAR file
3. For quick reloading during development: Ctrl/⌘ + click the Loaded checkbox

## Usage

1. Open the "Cognito" tab in Burp Suite
2. Enter your AWS Cognito access token
3. Enter the AWS region (e.g., `us-east-1`)
4. Click on the desired operation button:
   - **Get User** - Retrieves user information using the access token
   - **Update User Attributes** - Opens a dialog to update user attributes (enter JSON format)

## Notes

- AWS Cognito API requires AWS Signature Version 4 signing for authentication. This extension provides the basic request structure, but you may need to configure AWS credentials or modify the implementation for your specific authentication method.
- All HTTP requests are sent through Burp's HTTP API, so they will appear in Burp's HTTP history and can be intercepted/modified.
- Operations are executed in background threads to maintain UI responsiveness.

## Development

See `CLAUD.md` for architecture details and development guidelines.

