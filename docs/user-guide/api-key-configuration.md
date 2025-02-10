# API Key Configuration

Stack integrates with various threat intelligence platforms to provide comprehensive threat analysis. This guide explains how to configure API keys for different platforms.

## Available Platforms

### IBM X-Force
- **Configuration Required**: API Key and API Password
- **Get API Key**: Visit [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/settings/api)
- **Note**: Both API Key and API Password are required for authentication

### Hybrid Analysis
- **Configuration Required**: API Key and API Secret
- **Get API Key**: Visit [Hybrid Analysis](https://www.hybrid-analysis.com/my-account)
- **Note**: Both API Key and API Secret are required for authentication

### CrowdSec
- **Configuration Required**: API Key
- **Get API Key**: Visit [CrowdSec Console](https://app.crowdsec.net/settings/cti-api-keys)

### Pulsedive
- **Configuration Required**: API Key
- **Get API Key**: Visit [Pulsedive](https://pulsedive.com/api/)

## Configuration Steps

1. Navigate to Settings > API Configuration
2. Find the platform you want to configure
3. Click "Get API Key" to visit the platform's API key management page
4. Generate your API credentials on the platform's website
5. Copy and paste the credentials into Stack
6. Click "Save" to store your API key
7. Use "Test" to verify your API key is working correctly

## Security Notes

- All API keys are encrypted before being stored in the database
- Use the show/hide toggle to protect sensitive information
- You can delete API keys at any time using the "Delete" button
- Regular API key rotation is recommended for security

## Troubleshooting

If you encounter issues with your API keys:

1. Verify that you've entered both required fields for platforms that need them (e.g., IBM X-Force, Hybrid Analysis)
2. Use the "Test" button to check if your credentials are valid
3. Ensure you have the correct subscription level on the platform
4. Check if you've reached any API rate limits
