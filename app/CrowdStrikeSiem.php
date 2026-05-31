<?php

/**
 * CrowdStrikeSiem.php
 *
 * PHP version 7
 *
 * CrowdStrike SIEM connector for IAM audit log events
 *
 * @category  Security
 * @package   PassHub
 * @license   http://opensource.org/licenses/mit-license.php The MIT License
 */

namespace PassHub;

class CrowdStrikeSiem
{
    private $apiUrl;
    private $clientId;
    private $clientSecret;
    private $accessToken;
    private $tokenExpiry;
    private $enabled;
    
    public function __construct()
    {
        $this->enabled = defined('CROWDSTRIKE_SIEM_ENABLED') && CROWDSTRIKE_SIEM_ENABLED;
        
        if ($this->enabled) {
            $this->apiUrl = defined('CROWDSTRIKE_API_URL') ? CROWDSTRIKE_API_URL : 'https://api.crowdstrike.com';
            $this->clientId = defined('CROWDSTRIKE_CLIENT_ID') ? CROWDSTRIKE_CLIENT_ID : null;
            $this->clientSecret = defined('CROWDSTRIKE_CLIENT_SECRET') ? CROWDSTRIKE_CLIENT_SECRET : null;
            
            if (!$this->clientId || !$this->clientSecret) {
                Utils::err("CrowdStrike SIEM: Missing client credentials");
                $this->enabled = false;
            }
        }
    }
    
    /**
     * Send audit log event to CrowdStrike SIEM
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
            
            // Format the audit data for CrowdStrike
            $siemEvent = $this->formatAuditEvent($auditData);
            
            // Send to CrowdStrike
            return $this->sendEvent($siemEvent);
            
        } catch (Exception $e) {
            Utils::err("CrowdStrike SIEM error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Format audit event data for CrowdStrike SIEM
     */
    private function formatAuditEvent($auditData)
    {
        $event = [
            'timestamp' => isset($auditData['timestamp']) ? $auditData['timestamp'] : date('c'),
            'event_type' => 'iam_audit',
            'source' => 'passhub',
            'severity' => $this->getSeverityLevel($auditData['operation']),
            'category' => 'identity_access_management',
            'event_data' => [
                'actor' => $auditData['actor'] ?? 'unknown',
                'operation' => $auditData['operation'] ?? 'unknown',
                'user' => $auditData['user'] ?? null,
                'company' => $auditData['company'] ?? null,
                'group' => $auditData['group'] ?? null,
                'access_code' => $auditData['access_code'] ?? null,
            ],
            'metadata' => [
                'source_ip' => $_SERVER['REMOTE_ADDR'] ?? null,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'session_id' => session_id() ?? null,
                'server_name' => $_SERVER['SERVER_NAME'] ?? null,
            ]
        ];
        
        // Remove null values to clean up the payload
        $event['event_data'] = array_filter($event['event_data'], function($value) {
            return $value !== null;
        });
        
        $event['metadata'] = array_filter($event['metadata'], function($value) {
            return $value !== null;
        });
        
        return $event;
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
     * Get a new access token from CrowdStrike OAuth2
     */
    private function refreshAccessToken()
    {
        $tokenUrl = $this->apiUrl . '/oauth2/token';
        
        $postData = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'grant_type' => 'client_credentials'
        ];
        
        $curl = curl_init();
        curl_setopt_array($curl, [
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
        ]);
        
        $response = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $curlError = curl_error($curl);
        curl_close($curl);
        
        if ($curlError) {
            Utils::err("CrowdStrike token request cURL error: " . $curlError);
            return false;
        }
        
        if ($httpCode !== 200) {
            Utils::err("CrowdStrike token request failed with HTTP $httpCode: " . $response);
            return false;
        }
        
        $tokenData = json_decode($response, true);
        if (!$tokenData || !isset($tokenData['access_token'])) {
            Utils::err("CrowdStrike token response invalid: " . $response);
            return false;
        }
        
        $this->accessToken = $tokenData['access_token'];
        $this->tokenExpiry = time() + ($tokenData['expires_in'] ?? 3600) - 300; // 5 min buffer
        
        return true;
    }
    
    /**
     * Send formatted event to CrowdStrike SIEM
     */
    private function sendEvent($event)
    {
        $eventsUrl = $this->apiUrl . '/log-management/entities/saved-searches/ingest/v1';
        
        $payload = [
            'events' => [$event]
        ];
        
        $curl = curl_init();
        curl_setopt_array($curl, [
            CURLOPT_URL => $eventsUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($payload),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Accept: application/json',
                'Authorization: Bearer ' . $this->accessToken
            ],
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        
        $response = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $curlError = curl_error($curl);
        curl_close($curl);
        
        if ($curlError) {
            Utils::err("CrowdStrike event send cURL error: " . $curlError);
            return false;
        }
        
        if ($httpCode < 200 || $httpCode >= 300) {
            Utils::err("CrowdStrike event send failed with HTTP $httpCode: " . $response);
            return false;
        }
        
        // Log successful transmission for debugging
        Utils::log("CrowdStrike SIEM event sent successfully: " . $event['event_data']['operation'], "siem", "log");
        
        return true;
    }
}