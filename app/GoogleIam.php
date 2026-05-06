<?php

// Google Workspace / Cloud Identity IAM integration
// Uses Google Admin SDK Directory API to check group membership
// Analogous to Azure.php and LDAP.php

namespace PassHub;

require_once 'config/config.php';
require_once 'vendor/autoload.php';

use GuzzleHttp\Client;

class GoogleIam
{

    public static function Authenticate() {
        $url = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
            'client_id' => GOOGLE_IAM['client_id'],
            'redirect_uri' => 'https://' . $_SERVER['HTTP_HOST'] . '/google-oauth-callback.php',
            'response_type' => 'code',
            'scope' => 'openid email profile',
            'access_type' => 'offline',
            'prompt' => 'select_account',
            'state' => $_SESSION['csrf_token'] ?? bin2hex(random_bytes(16)),
        ]);

        header("Location: $url");
    }

    public static function checkAccess($email) {
        $groupsArray = self::getUsers();
        $userEmails = $groupsArray["user_upns"];
        $adminEmails = $groupsArray["admin_upns"];
        $userFound = false;

        $email = strtolower($email);

        for ($i = 0; $i < count($userEmails); $i++) {
            if (strtolower($userEmails[$i]) == $email) {
                $userFound = true;
                break;
            }
        }
        if ($userFound) {
            for ($j = 0; $j < count($adminEmails); $j++) {
                if (strtolower($adminEmails[$j]) == $email) {
                    $_SESSION['admin'] = true;
                    break;
                }
            }
        }
        return $userFound;
    }

    public static function getUsers() {
        $accessToken = self::getServiceAccessToken();
        $userGroupEmail = GOOGLE_IAM['user_group'];
        $adminGroupEmail = GOOGLE_IAM['admin_group'];
        $user_upns = [];
        $admin_upns = [];

        $guzzle = new \GuzzleHttp\Client();

        // Get members of user group
        $nextPageToken = null;
        do {
            $url = 'https://admin.googleapis.com/admin/directory/v1/groups/' 
                . urlencode($userGroupEmail) . '/members';
            $params = ['maxResults' => 200];
            if ($nextPageToken) {
                $params['pageToken'] = $nextPageToken;
            }
            $response = $guzzle->request('GET', $url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $accessToken
                ],
                'query' => $params
            ]);
            $body = json_decode($response->getBody(), true);
            if (isset($body['members'])) {
                foreach ($body['members'] as $member) {
                    if (!empty($member['email'])) {
                        $user_upns[] = strtolower($member['email']);
                    }
                }
            }
            $nextPageToken = $body['nextPageToken'] ?? null;
        } while ($nextPageToken);

        // Get members of admin group
        $nextPageToken = null;
        do {
            $url = 'https://admin.googleapis.com/admin/directory/v1/groups/' 
                . urlencode($adminGroupEmail) . '/members';
            $params = ['maxResults' => 200];
            if ($nextPageToken) {
                $params['pageToken'] = $nextPageToken;
            }
            $response = $guzzle->request('GET', $url, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $accessToken
                ],
                'query' => $params
            ]);
            $body = json_decode($response->getBody(), true);
            if (isset($body['members'])) {
                foreach ($body['members'] as $member) {
                    if (!empty($member['email'])) {
                        $admin_upns[] = strtolower($member['email']);
                    }
                }
            }
            $nextPageToken = $body['nextPageToken'] ?? null;
        } while ($nextPageToken);

        return ["user_upns" => $user_upns, "admin_upns" => $admin_upns];
    }

    /**
     * Get an access token using a service account (server-to-server).
     * Requires a service account JSON key file with domain-wide delegation
     * and the Admin SDK Directory API enabled.
     */
    public static function getServiceAccessToken() {
        $serviceAccountFile = GOOGLE_IAM['service_account_file'];
        $delegateEmail = GOOGLE_IAM['admin_email'];

        $sa = json_decode(file_get_contents($serviceAccountFile), true);

        $now = time();
        $header = self::base64url(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
        $claimSet = self::base64url(json_encode([
            'iss' => $sa['client_email'],
            'sub' => $delegateEmail,
            'scope' => 'https://www.googleapis.com/auth/admin.directory.group.member.readonly',
            'aud' => 'https://oauth2.googleapis.com/token',
            'iat' => $now,
            'exp' => $now + 3600,
        ]));

        $signatureInput = $header . '.' . $claimSet;
        openssl_sign($signatureInput, $signature, $sa['private_key'], 'SHA256');
        $jwt = $signatureInput . '.' . self::base64url($signature);

        $guzzle = new \GuzzleHttp\Client();
        $response = $guzzle->post('https://oauth2.googleapis.com/token', [
            'form_params' => [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion' => $jwt,
            ],
        ]);

        $token = json_decode($response->getBody()->getContents(), true);
        return $token['access_token'];
    }

    /**
     * Exchange an authorization code for user tokens (used in OAuth callback).
     */
    public static function exchangeCode($code) {
        $guzzle = new \GuzzleHttp\Client();
        $response = $guzzle->post('https://oauth2.googleapis.com/token', [
            'form_params' => [
                'code' => $code,
                'client_id' => GOOGLE_IAM['client_id'],
                'client_secret' => GOOGLE_IAM['client_secret'],
                'redirect_uri' => 'https://' . $_SERVER['HTTP_HOST'] . '/google-oauth-callback.php',
                'grant_type' => 'authorization_code',
            ],
        ]);
        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * Get user info from Google using an access token.
     */
    public static function getUserInfo($accessToken) {
        $guzzle = new \GuzzleHttp\Client();
        $response = $guzzle->request('GET', 'https://www.googleapis.com/oauth2/v2/userinfo', [
            'headers' => [
                'Authorization' => 'Bearer ' . $accessToken,
            ],
        ]);
        return json_decode($response->getBody()->getContents(), true);
    }

    private static function base64url($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
