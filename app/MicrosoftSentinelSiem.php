<?php

/**
 * MicrosoftSentinelSiem.php
 *
 * PHP version 7
 *
 * Microsoft Sentinel (Azure Monitor Logs Ingestion API) connector for IAM audit log events
 *
 * @category  Security
 * @package   PassHub
 * @license   http://opensource.org/licenses/mit-license.php The MIT License
 */



namespace PassHub;

class MicrosoftSentinelSiem
{
    private $tenantId;
    private $clientId;
    private $clientSecret;
    private $dceEndpoint;
    private $dcrImmutableId;
    private $streamName;
    private $accessToken;
    private $tokenExpiry;
    private $enabled;

    public function __construct()
    {
        $this->enabled = defined('MS_SENTINEL_ENABLED') && MS_SENTINEL_ENABLED;

        if ($this->enabled) {
            $this->tenantId = defined('MS_SENTINEL_TENANT_ID') ? MS_SENTINEL_TENANT_ID : null;
            $this->clientId = defined('MS_SENTINEL_CLIENT_ID') ? MS_SENTINEL_CLIENT_ID : null;
            $this->clientSecret = defined('MS_SENTINEL_CLIENT_SECRET') ? MS_SENTINEL_CLIENT_SECRET : null;
            $this->dceEndpoint = defined('MS_SENTINEL_DCE_ENDPOINT') ? rtrim(MS_SENTINEL_DCE_ENDPOINT, '/') : null;
            $this->dcrImmutableId = defined('MS_SENTINEL_DCR_IMMUTABLE_ID') ? MS_SENTINEL_DCR_IMMUTABLE_ID : null;
            $this->streamName = defined('MS_SENTINEL_STREAM_NAME') ? MS_SENTINEL_STREAM_NAME : 'Custom-PassHubAuditLogs_CL';

            if (!$this->tenantId || !$this->clientId || !$this->clientSecret
                || !$this->dceEndpoint || !$this->dcrImmutableId
            ) {
                Utils::err("Microsoft Sentinel SIEM: Missing configuration (tenant/client/endpoint/DCR)");
                $this->enabled = false;
            }
        }
    }

    /**
     * Send audit log event to Microsoft Sentinel
     */
    public function sendAuditEvent($auditData)
    {
        if (!$this->enabled) {
            return false;
        }

        try {
            // Ensure we have a valid access token
            if (!$this->ensureAccessToken()) {
                return false;
            }

            // Format the audit data for the Logs Ingestion API / DCR schema
            $siemEvent = $this->formatAuditEvent($auditData);

            // Send to Microsoft Sentinel
            return $this->sendEvent($siemEvent);

        } catch (Exception $e) {
            Utils::err("Microsoft Sentinel SIEM error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Format audit event data for the Data Collection Rule custom table schema
     */
    private function formatAuditEvent($auditData)
    {
        $event = [
            'TimeGenerated' => isset($auditData['timestamp']) ? $auditData['timestamp'] : date('c'),
            'EventType' => 'iam_audit',
            'Source' => 'passhub',
            'Severity' => $this->getSeverityLevel($auditData['operation']),
            'Category' => 'identity_access_management',
            'Actor' => $auditData['actor'] ?? 'unknown',
            'Operation' => $auditData['operation'] ?? 'unknown',
            'TargetUser' => $auditData['user'] ?? null,
            'Company' => $auditData['company'] ?? null,
            'Group' => $auditData['group'] ?? null,
            'AccessCode' => $auditData['access_code'] ?? null,
            'SourceIp' => $_SERVER['REMOTE_ADDR'] ?? null,
            'UserAgent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'SessionId' => session_id() ?: null,
            'ServerName' => $_SERVER['SERVER_NAME'] ?? null,
        ];

        // Remove null values to clean up the payload
        return array_filter(
            $event, function ($value) {
                return $value !== null;
            }
        );
    }

    /**
     * Determine severity level based on operation type
     */
    private function getSeverityLevel($operation)
    {
        $highSeverityOps = [
            'deleteAccount',
            'statusAdmin',
            'statusDisabled',
            'deleteInvitation',
            'Delete group'
        ];

        $mediumSeverityOps = [
            'statusActive',
            'Create account',
            'addCompany',
            'setCompanyProfile'
        ];

        if (in_array($operation, $highSeverityOps)) {
            return 'high';
        } elseif (in_array($operation, $mediumSeverityOps)) {
            return 'medium';
        }

        return 'low';
    }

    /**
     * Ensure we have a valid access token
     */
    private function ensureAccessToken()
    {
        if ($this->accessToken && $this->tokenExpiry > time()) {
            return true;
        }

        return $this->refreshAccessToken();
    }

    /**
     * Get a new access token from Azure AD (client credentials flow), scoped
     * to the Azure Monitor Logs Ingestion API.
     */
    private function refreshAccessToken()
    {
        $tokenUrl = 'https://login.microsoftonline.com/' . $this->tenantId . '/oauth2/v2.0/token';

        $postData = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'scope' => 'https://monitor.azure.com/.default',
            'grant_type' => 'client_credentials'
        ];

        $curl = curl_init();
        curl_setopt_array(
            $curl, [
            CURLOPT_URL => $tokenUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($postData),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json'
            ],
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            ]
        );

        $response = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $curlError = curl_error($curl);
        curl_close($curl);

        if ($curlError) {
            Utils::err("Microsoft Sentinel token request cURL error: " . $curlError);
            return false;
        }

        if ($httpCode !== 200) {
            Utils::err("Microsoft Sentinel token request failed with HTTP $httpCode: " . $response);
            return false;
        }

        $tokenData = json_decode($response, true);
        if (!$tokenData || !isset($tokenData['access_token'])) {
            Utils::err("Microsoft Sentinel token response invalid: " . $response);
            return false;
        }

        $this->accessToken = $tokenData['access_token'];
        $this->tokenExpiry = time() + ($tokenData['expires_in'] ?? 3600) - 300; // 5 min buffer

        return true;
    }

    /**
     * Send formatted event to the Microsoft Sentinel workspace via the
     * Azure Monitor Logs Ingestion API (Data Collection Rule / Endpoint).
     */
    private function sendEvent($event)
    {
        $ingestUrl = $this->dceEndpoint
            . '/dataCollectionRules/' . $this->dcrImmutableId
            . '/streams/' . $this->streamName
            . '?api-version=2023-01-01';

        // The Logs Ingestion API expects a JSON array of records
        $payload = [$event];

        $curl = curl_init();
        curl_setopt_array(
            $curl, [
            CURLOPT_URL => $ingestUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($payload),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $this->accessToken
            ],
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            ]
        );

        $response = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $curlError = curl_error($curl);
        curl_close($curl);

        if ($curlError) {
            Utils::err("Microsoft Sentinel event send cURL error: " . $curlError);
            return false;
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            Utils::err("Microsoft Sentinel event send failed with HTTP $httpCode: " . $response);
            return false;
        }

        // Log successful transmission for debugging
        Utils::log("Microsoft Sentinel SIEM event sent successfully: " . $event['Operation'], "siem", "log");

        return true;
    }
}
