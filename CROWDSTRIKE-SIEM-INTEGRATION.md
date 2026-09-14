# CrowdStrike SIEM Integration for PassHub

This document explains how to configure and use the CrowdStrike connector (`app/CrowdStrikeSiem.php`) for PassHub IAM audit events.

## Overview

The CrowdStrike connector forwards all IAM audit events from PassHub to **Falcon Next-Gen SIEM** (built on Falcon LogScale) in real time, using LogScale's **HTTP Event Collector (HEC)** ingest API. Authentication uses a static HEC ingest token — there is no OAuth2 token exchange involved, so setup only requires a URL and a token.

> Earlier revisions of this connector used an OAuth2 client-credentials flow against `api.crowdstrike.com`. That endpoint does not exist for third-party log ingestion — HEC is the supported mechanism, so the connector was rewritten around it.

## Supported Events

Same events as the Microsoft Sentinel connector:

- **User Management**: Account creation, deletion, status changes (active/disabled/admin)
- **Invitations**: User invitations and invitation management
- **Company Management**: Company profile changes and administration
- **Group Management**: Group creation, deletion, user/safe additions/removals
- **Access Control**: Role changes and permission modifications

## Event Data Structure

Each call to `sendAuditEvent()` wraps the audit fields in a Splunk HEC-compatible envelope and posts it as JSON:

```json
{
  "time": 1784304600,
  "host": "passhub.company.com",
  "source": "passhub",
  "sourcetype": "passhub:audit",
  "event": {
    "timestamp": "2026-07-14T10:30:00+00:00",
    "event_type": "iam_audit",
    "category": "identity_access_management",
    "severity": "high|medium|low",
    "actor": "admin@company.com",
    "operation": "deleteAccount",
    "user": "user@company.com",
    "company": "company_id",
    "group": "group_name",
    "source_ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "session_id": "sess_123456"
  }
}
```

Fields with no value (e.g. `group` when the operation isn't group-related) are omitted rather than sent as `null`.

## Setup Instructions

### 1. Create a HEC data source in Falcon Next-Gen SIEM

1. Log in to the Falcon console and open **Next-Gen SIEM > Data sources** (or, within a LogScale repo, **Settings > Ingest tokens**).
2. Click **Add source** / **Add new HTTP Event Collector token**.
3. Configure:
   - **Name**: `PassHub SIEM Connector`
   - **Parser**: leave as the default JSON parser (or select `hec` if prompted)
4. Save and copy the generated **ingest token** — this is shown only once.
5. Note the **ingest URL** for your CrowdStrike cloud region, e.g.:
   - `https://<your-cid>.ingest.us-1.crowdstrike.com/api/v1/ingest/hec/event`
   - `https://<your-cid>.ingest.us-2.crowdstrike.com/api/v1/ingest/hec/event`
   - `https://<your-cid>.ingest.eu-1.crowdstrike.com/api/v1/ingest/hec/event`

   (The exact hostname is shown alongside the token in the console — use that value rather than guessing the region.)

### 2. PassHub Configuration

Edit your PassHub configuration file (`config/config.php`) and add:

```php
// Enable CrowdStrike SIEM connector
define('CROWDSTRIKE_SIEM_ENABLED', true);

// Falcon LogScale HEC ingest URL (from the console, step 1 above)
define('CROWDSTRIKE_INGEST_URL', 'https://your-logscale-host/api/v1/ingest/hec/event');

// HEC ingest token
define('CROWDSTRIKE_HEC_TOKEN', 'your_hec_ingest_token_here');

// Optional — all default sensibly if omitted
define('CROWDSTRIKE_HEC_SOURCE', 'passhub');
define('CROWDSTRIKE_HEC_SOURCETYPE', 'passhub:audit');
define('CROWDSTRIKE_HEC_HOST', 'passhub.company.com');
```

If `CROWDSTRIKE_INGEST_URL` or `CROWDSTRIKE_HEC_TOKEN` is missing, the connector logs an error and disables itself — it never blocks or fails the underlying audit write to MongoDB.

### 3. Test the Integration

1. Restart your web server after configuration changes.
2. Perform a test IAM operation (e.g., invite a user).
3. Check PassHub logs (`LOG_DIR/siem-*.log`) for a "CrowdStrike SIEM event sent successfully" line.
4. In the Falcon console, search the repo/log source for `sourcetype=passhub:audit` (or your custom `CROWDSTRIKE_HEC_SOURCETYPE`) to confirm events are arriving.

## Event Severity Levels

Same severity mapping as the Microsoft Sentinel connector:

**High Severity:** `deleteAccount`, `statusAdmin`, `statusDisabled`, `Delete group`, `deleteInvitation`

**Medium Severity:** `statusActive`, `Create account`, `addCompany`, `setCompanyProfile`

**Low Severity:** all other operations (invitations, group membership changes, etc.)

## Error Handling and Monitoring

### Logging

- Success: `LOG_DIR/siem-YYMMDD.log`
- Errors: `LOG_DIR/passhub-YYMMDD.err`

**Important**: SIEM integration failures do not affect PassHub's core audit logging functionality. Events are always stored in the local MongoDB `audit` collection regardless of CrowdStrike connectivity.

## Troubleshooting

1. **Events not appearing in Falcon Next-Gen SIEM**
   - Verify `CROWDSTRIKE_INGEST_URL` matches the host shown next to your HEC token in the console.
   - Confirm the HEC token hasn't been revoked or regenerated.
   - Check PassHub error logs for the HTTP status code returned by the ingest endpoint.
2. **Authentication failures (HTTP 401/403)**
   - Verify `CROWDSTRIKE_HEC_TOKEN` is correct and active.
   - Regenerate the token in the console if needed and update `config.php`.
3. **Malformed event errors (HTTP 400)**
   - Confirm the payload matches the HEC envelope shape (`time`/`host`/`source`/`sourcetype`/`event`) — this should not occur unless the connector code has been modified.
4. **Network connectivity issues**
   - Verify outbound HTTPS (443) access to your ingest host.
   - Test connectivity: `curl -I https://your-logscale-host`

## Security Considerations

1. Store the HEC ingest token securely; it is a bearer credential with no expiry by default — rotate it periodically from the console.
2. Restrict access to `config/config.php`.
3. Use TLS (enforced by the ingest endpoint) for all traffic.
4. Treat the ingest URL/token pair as sensitive — anyone with both can write arbitrary events into your CrowdStrike repo.

## Version History

- **v2.0**: Rewritten around Falcon LogScale HTTP Event Collector (HEC)
  - Static ingest-token authentication, no OAuth2 token refresh needed
  - Simplified, accurate to CrowdStrike's actual third-party log ingestion API
- **v1.0**: Initial CrowdStrike SIEM integration (OAuth2 client-credentials, retired)
