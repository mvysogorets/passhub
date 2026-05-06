# CrowdStrike SIEM Integration for PassHub

This document explains how to configure and use the CrowdStrike SIEM connector for PassHub IAM audit events.

## Overview

The CrowdStrike SIEM connector automatically forwards all IAM audit events from PassHub to your CrowdStrike Falcon platform for security monitoring and analysis. Events are sent in real-time as they occur, providing comprehensive visibility into user access management activities.

## Supported Events

The connector captures all IAM audit events including:

- **User Management**: Account creation, deletion, status changes (active/disabled/admin)
- **Invitations**: User invitations and invitation management
- **Company Management**: Company profile changes and administration
- **Group Management**: Group creation, deletion, user/safe additions/removals
- **Access Control**: Role changes and permission modifications

## Event Data Structure

Events sent to CrowdStrike include:

```json
{
  "timestamp": "2026-03-12T10:30:00Z",
  "event_type": "iam_audit",
  "source": "passhub",
  "severity": "high|medium|low",
  "category": "identity_access_management",
  "event_data": {
    "actor": "admin@company.com",
    "operation": "deleteAccount",
    "user": "user@company.com",
    "company": "company_id",
    "group": "group_name"
  },
  "metadata": {
    "source_ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "session_id": "sess_123456",
    "server_name": "passhub.company.com"
  }
}
```

## Setup Instructions

### 1. CrowdStrike Falcon Console Setup

1. Log in to your CrowdStrike Falcon console
2. Navigate to **Support > API Clients and Keys**
3. Click **Add new API client**
4. Configure the API client:
   - **Client Name**: PassHub SIEM Connector
   - **Description**: PassHub IAM audit event integration
   - **Scopes**: Select **Event streams: READ**
5. Click **Add** and save the generated **Client ID** and **Client Secret**

### 2. PassHub Configuration

1. Edit your PassHub configuration file (`config/config.php`)
2. Add the following configuration options:

```php
// Enable CrowdStrike SIEM connector
define('CROWDSTRIKE_SIEM_ENABLED', true);

// CrowdStrike API endpoint (choose based on your region)
define('CROWDSTRIKE_API_URL', 'https://api.crowdstrike.com'); // US-1 (default)
// define('CROWDSTRIKE_API_URL', 'https://api.us-2.crowdstrike.com'); // US-2
// define('CROWDSTRIKE_API_URL', 'https://api.eu-1.crowdstrike.com'); // EU-1

// CrowdStrike API credentials
define('CROWDSTRIKE_CLIENT_ID', 'your_client_id_here');
define('CROWDSTRIKE_CLIENT_SECRET', 'your_client_secret_here');
```

### 3. Test the Integration

1. Restart your web server after configuration changes
2. Perform a test IAM operation (e.g., invite a user)
3. Check PassHub logs (`LOG_DIR/siem-*.log`) for successful transmission messages
4. Verify events appear in CrowdStrike Falcon under **Investigate > Event Search**

## Event Severity Levels

The connector automatically assigns severity levels based on the operation type:

**High Severity:**
- Account deletion (`deleteAccount`)
- Admin role assignment (`statusAdmin`)
- Account disabling (`statusDisabled`)
- Group deletion (`Delete group`)
- Invitation deletion (`deleteInvitation`)

**Medium Severity:**
- Account activation (`statusActive`)
- Account creation (`Create account`)
- Company management (`addCompany`, `setCompanyProfile`)

**Low Severity:**
- User invitations (`invite`)
- Group operations (add/remove users/safes)
- Other routine operations

## Error Handling and Monitoring

### Logging

The connector logs all activities to separate log files:
- Success: `LOG_DIR/siem-YYMMDD.log`
- Errors: `LOG_DIR/passhub-YYMMDD.err`

### Error Scenarios

The connector handles various error conditions:

1. **Configuration Errors**: Missing or invalid credentials
2. **Network Errors**: Connection timeouts or failures
3. **API Errors**: CrowdStrike API rate limiting or service issues
4. **Authentication Errors**: Token expiration or invalid credentials

**Important**: SIEM integration failures do not affect PassHub's core audit logging functionality. Events are always stored in the local MongoDB audit collection regardless of SIEM status.

## Troubleshooting

### Common Issues

1. **Events not appearing in CrowdStrike**
   - Verify API credentials are correct
   - Check the appropriate API URL for your region
   - Ensure the API client has proper permissions
   - Check PassHub error logs for transmission failures

2. **Authentication failures**
   - Verify Client ID and Client Secret
   - Check if API client is active in CrowdStrike console
   - Ensure proper scopes are assigned

3. **Network connectivity issues**
   - Verify outbound HTTPS (443) access to CrowdStrike API endpoints
   - Check proxy/firewall configurations
   - Test connectivity: `curl -I https://api.crowdstrike.com`

### Debug Mode

To enable detailed logging, monitor the error log file for CrowdStrike-related messages:

```bash
tail -f /var/log/passhub/passhub-$(date +%y%m%d).err | grep -i crowdstrike
```

## Security Considerations

1. **Credential Protection**: Store CrowdStrike API credentials securely
2. **Network Security**: Use encrypted connections (TLS/SSL) only  
3. **Access Control**: Restrict access to configuration files
4. **Key Rotation**: Regularly rotate API client credentials
5. **Monitoring**: Monitor for failed authentication attempts

## Support

For issues with this integration:

1. Check PassHub logs for error messages
2. Verify CrowdStrike API client configuration  
3. Test network connectivity to CrowdStrike endpoints
4. Contact your CrowdStrike support team for API-related issues

## Version History

- **v1.0**: Initial CrowdStrike SIEM integration
  - Real-time IAM event forwarding
  - OAuth2 authentication with token refresh
  - Configurable severity levels
  - Comprehensive error handling and logging