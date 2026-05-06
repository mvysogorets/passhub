<?php

require_once 'config/config.php';
require_once 'vendor/autoload.php';

use PassHub\Utils;
use PassHub\GoogleIam;

$mng = PassHub\DB::Connection();

session_start();

if (!isset($_SESSION['PUID'])) {
    header('HTTP/1.1 403 Forbidden');
    exit();
}

if (!array_key_exists("code", $_GET) || !array_key_exists("state", $_GET)) {
    header('HTTP/1.1 400 Bad Request');
    exit();
}

$code = $_GET['code'];

try {
    $tokens = GoogleIam::exchangeCode($code);
} catch (Exception $e) {
    Utils::err('Google OAuth Exception');
    Utils::err($e->getMessage());
    Utils::errorPage("Authentication error. Please try again.");
    exit();
}

if (!isset($tokens['access_token'])) {
    Utils::err('Google OAuth: no access_token in response');
    Utils::errorPage("Authentication error. Please try again.");
    exit();
}

$accessToken = $tokens['access_token'];

try {
    $userInfo = GoogleIam::getUserInfo($accessToken);
} catch (Exception $e) {
    Utils::err('Google userinfo Exception');
    Utils::err($e->getMessage());
    Utils::errorPage("Failed to retrieve user information.");
    exit();
}

$email = $userInfo['email'] ?? null;
$userprincipalname = $email; // Google uses email as principal name

if (is_null($email)) {
    $_SESSION = array();
    session_destroy();
    echo Utils::render(
        'error_page.html',
        [
            'narrow' => true,
            'hide_logout' => true,
            'PUBLIC_SERVICE' => defined('PUBLIC_SERVICE') ? PUBLIC_SERVICE : false,
            'header' => 'Access denied',
            'text' => 'Please contact your system administrator'
        ]
    );
    Utils::err("Google OAuth: no email returned");
    exit();
}

Utils::err('Google OAuth email: ' . $email);

// check if this userprincipalname exists
$count = $mng->users->countDocuments(['userprincipalname' => $userprincipalname]);
if ($count == 0) {
    $_SESSION['userprincipalname'] = $userprincipalname;
    $_SESSION['email'] = $email;
    if (!GoogleIam::checkAccess($email)) {
        $_SESSION = array();
        session_destroy();
        echo Utils::render(
            'error_page.html',
            [
                'narrow' => true,
                'hide_logout' => true,
                'PUBLIC_SERVICE' => defined('PUBLIC_SERVICE') ? PUBLIC_SERVICE : false,
                'header' => 'Access denied',
                'text' => 'Please contact your system administrator'
            ]
        );
        Utils::err("User not in Google IAM group");
        exit();
    }

    Utils::showCreateUserPage();
    exit();
}
Utils::err("userprincipalname $userprincipalname already exists");

Utils::messagePage("Error SSO 85", "<p>Please contact your system administrator</p>", true);
