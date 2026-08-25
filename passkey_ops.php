<?php

/**
 * passkey_ops.php
 *
 * PHP version 7
 *
 * Operations with Passkey records
 *
 * @category  Password_Manager
 * @package   PassHub
 * @author    Mikhail Vysogorets <m.vysogorets@wwpass.com>, Ann Savoy
 * @copyright 2026 WWPass
 * @license   http://opensource.org/licenses/mit-license.php The MIT License
 */

require_once 'config/config.php';
require_once 'vendor/autoload.php';

use PassHub\Utils;
use PassHub\DB;
use PassHub\User;
use PassHub\Passkey;
use PassHub\Csrf;

$mng = DB::Connection();

session_start();

function passkey_ops_proxy($mng) {

    if (!isset($_SESSION['UserID'])) {
        return "login";
    }

    // Takes raw data from the request
    $json = file_get_contents('php://input');

    // Converts it into a PHP object
    $req = json_decode($json);

    if (!$req) {
        return ['status' => 'error', 'message' => 'Invalid JSON'];
    }
   
    if(!Csrf::validCSRF($req)) {
        Utils::err("bad csrf");
        return ['status' => "Bad Request"];
    }

    $UserID = $_SESSION['UserID'];

    // Get list of passkeys for a specific rpId
    if (isset($req->operation) && $req->operation === 'getPasskeysForRpId') {
        if (!isset($req->rpId)) {
            return ['status' => 'error', 'message' => 'rpId required'];
        }
        
        try {
            $passkeys = Passkey::getPasskeysForRpId($mng, $UserID, $req->rpId);
            return [
                'status' => 'Ok',
                'passkeys' => $passkeys
            ];
        } catch (Exception $e) {
            Utils::err('Error getting passkeys: ' . $e->getMessage());
            return ['status' => 'error', 'message' => 'Server error'];
        }
    }

    // Increment counter after using passkey
    if (isset($req->operation) && $req->operation === 'incrementCounter') {
        if (!isset($req->itemId)) {
            return ['status' => 'error', 'message' => 'itemId required'];
        }
        
        try {
            $success = Passkey::incrementCounter($mng, $UserID, $req->itemId);
            if ($success) {
                Utils::log("user $UserID activity passkey used (counter incremented)");
                return ['status' => 'Ok'];
            } else {
                return ['status' => 'error', 'message' => 'Failed to increment counter'];
            }
        } catch (Exception $e) {
            Utils::err('Error incrementing counter: ' . $e->getMessage());
            return ['status' => 'error', 'message' => 'Server error'];
        }
    }

    // Get passkey statistics
    if (isset($req->operation) && $req->operation === 'getStats') {
        try {
            $stats = Passkey::getStats($mng, $UserID);
            return [
                'status' => 'Ok',
                'stats' => $stats
            ];
        } catch (Exception $e) {
            Utils::err('Error getting stats: ' . $e->getMessage());
            return ['status' => 'error', 'message' => 'Server error'];
        }
    }

    // Validate passkey structure
    if (isset($req->operation) && $req->operation === 'validate') {
        if (!isset($req->passkey)) {
            return ['status' => 'error', 'message' => 'passkey data required'];
        }
        
        $validation = Passkey::validate($req->passkey);
        if ($validation['valid']) {
            return ['status' => 'Ok', 'valid' => true];
        } else {
            return [
                'status' => 'error',
                'valid' => false,
                'message' => $validation['error']
            ];
        }
    }

    return ['status' => 'error', 'message' => 'Unknown operation'];
}

header('Content-type: application/json');
header('Cache-Control: no-cache, must-revalidate');
header('Expires: Mon, 01 Jan 1996 00:00:00 GMT');

$result = passkey_ops_proxy($mng);
if (gettype($result) == "string") {
    $result = array("status" => $result);
}

// Send the data.
echo json_encode($result);
