<?php

/**
 * CrowdStrikeSiem.php
 *
 * PHP version 7
 *
 * CrowdStrike Falcon Next-Gen SIEM (Falcon LogScale HTTP Event Collector)
 * connector for IAM audit log events.
 *
 * @category  Security
 * @package   PassHub
 * @license   http://opensource.org/licenses/mit-license.php The MIT License
 */

namespace PassHub;

class CrowdStrikeSiem
{
    private $ingestUrl;
    private $hecToken;
    private $source;
    private $sourcetype;
    private $host;
    private $enabled;

    public function __construct()
    {
        $this->enabled = defined('CROWDSTRIKE_SIEM_ENABLED') && CROWDSTRIKE_SIEM_ENABLED;

        if ($this->enabled) {
            $this->ingestUrl = defined('CROWDSTRIKE_INGEST_URL') ? CROWDSTRIKE_INGEST_URL : null;
            $this->hecToken = defined('CROWDSTRIKE_HEC_TOKEN') ? CROWDSTRIKE_HEC_TOKEN : null;
            $this->source = defined('CROWDSTRIKE_HEC_SOURCE') ? CROWDSTRIKE_HEC_SOURCE : 'passhub';
            $this->sourcetype = defined('CROWDSTRIKE_HEC_SOURCETYPE') ? CROWDSTRIKE_HEC_SOURCETYPE : 'passhub:audit';
            $this->host = defined('CROWDSTRIKE_HEC_HOST') ? CROWDSTRIKE_HEC_HOST : ($_SERVER['SERVER_NAME'] ?? 'passhub');

            if (!$this->ingestUrl || !$this->hecToken) {
                Utils::err("CrowdStrike SIEM: Missing ingest URL or HEC token");
                $this->enabled = false;
            }
        }
    }

    /**
     * Send an audit log event to CrowdStrike Falcon Next-Gen SIEM
     */
    public function sendAuditEvent($auditData)
    {
        if (!$this->enabled) {
            return false;
        }

        try {
            $hecEvent = $this->formatAuditEvent($auditData);
            return $this->sendEvent($hecEvent);
        } catch (\Exception $e) {
            Utils::err("CrowdStrike SIEM error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Build a Splunk HEC-compatible event envelope, the format LogScale's
     * ingest API expects: a time/host/source/sourcetype wrapper around the
     * actual event payload.
     */
    private function formatAuditEvent($auditData)
    {
        $eventTime = isset($auditData['timestamp']) ? strtotime($auditData['timestamp']) : time();

        $fields = array_filter(
            [
                'timestamp' => isset($auditData['timestamp']) ? $auditData['timestamp'] : date('c'),
                'event_type' => 'iam_audit',
                'category' => 'identity_access_management',
                'severity' => $this->getSeverityLevel($auditData['operation'] ?? null),
                'actor' => $auditData['actor'] ?? 'unknown',
                'operation' => $auditData['operation'] ?? 'unknown',
                'user' => $auditData['user'] ?? null,
                'company' => $auditData['company'] ?? null,
                'group' => $auditData['group'] ?? null,
                'source_ip' => $_SERVER['REMOTE_ADDR'] ?? null,
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'session_id' => session_id() ?: null,
            ], function ($value) {
                return $value !== null;
            }
        );

        return [
            'time' => $eventTime,
            'host' => $this->host,
            'source' => $this->source,
            'sourcetype' => $this->sourcetype,
            'event' => $fields,
        ];
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
            'Delete group',
        ];

        $mediumSeverityOps = [
            'statusActive',
            'Create account',
            'addCompany',
            'setCompanyProfile',
        ];

        if (in_array($operation, $highSeverityOps, true)) {
            return 'high';
        } elseif (in_array($operation, $mediumSeverityOps, true)) {
            return 'medium';
        }

        return 'low';
    }

    /**
     * POST the event to the Falcon LogScale HTTP Event Collector endpoint
     */
    private function sendEvent($hecEvent)
    {
        $curl = curl_init();
        curl_setopt_array(
            $curl, [
            CURLOPT_URL => $this->ingestUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($hecEvent),
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $this->hecToken,
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
            Utils::err("CrowdStrike SIEM cURL error: " . $curlError);
            return false;
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            Utils::err("CrowdStrike SIEM ingest failed with HTTP $httpCode: " . $response);
            return false;
        }

        Utils::log("CrowdStrike SIEM event sent successfully: " . $hecEvent['event']['operation'], "siem", "log");

        return true;
    }
}