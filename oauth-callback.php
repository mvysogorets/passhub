<?php

require_once 'config/config.php';
require_once 'vendor/autoload.php';

use PassHub\Utils;
use PassHub\Azure;

use Microsoft\Graph\Graph;
use Microsoft\Graph\Model;
use GuzzleHttp\Client;

$mng = PassHub\DB::Connection();

session_start();

if (!isset($_SESSION['PUID'])) {
    header('HTTP/1.1 403 Forbidden');
    exit();
}

if ( !array_key_exists("code",$_GET)  || !array_key_exists("state",$_GET) ) {
    header('HTTP/1.1 400 Bad Request');
    exit();
}

$code = $_GET['code'];
$state = $_GET['state'];

$clientId = AZURE['application_client_id'];
$tenantId = AZURE['directory_tenant_id'];
$clientSecret = AZURE['client_value'];

$userGroupUrl = AZURE['user_group'];
$adminGroupUrl = AZURE['admin_group'];


$guzzle = new \GuzzleHttp\Client();
$url = 'https://login.microsoftonline.com/' . $tenantId . '/oauth2/v2.0/token?api-version=1.0';

try {
    $token = json_decode($guzzle->post($url, [
        'form_params' => [
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => 'https://' . $_SERVER['HTTP_HOST'] . '/oauth-callback.php'
//            'scope' => 'https://graph.microsoft.com/.default',
        ],
    ])->getBody()->getContents());
} catch (Exception $e) {
    Utils::err('Exception');
    Utils::err($e->getMessage());
    print($e->getMessage());
    exit();
}


$accessToken = $token->access_token;

$graph = new Graph();
$graph->setBaseUrl("https://graph.microsoft.com/")
        ->setAccessToken($accessToken);


$me = $graph->createRequest("get", "/me")
        ->setReturnType(Model\User::class)
        ->execute();

Utils::err("me");
Utils::err($me);

$userprincipalname = $me->getUserPrincipalName();
$email = $me->getMail();

if(is_null($email)) {
    $_SESSION = array();
    session_destroy();
    echo Utils::render(
        'error_page.html',
        [
            // layout
            'narrow' => true,
            'hide_logout' => true,
            'PUBLIC_SERVICE' => defined('PUBLIC_SERVICE') ? PUBLIC_SERVICE : false,
            'header' => 'Access denied',
            'text' => 'Please contact your system administrator'
        ]
    );
    Utils::err("Please add an Email to this User!");
     exit();
}
Utils::err('----' . $me->getUserPrincipalName());
Utils::err('----' . $me->getMail());


// check if this userprincipalname exists
$count = $mng->users->countDocuments(['userprincipalname' => $userprincipalname]);
if($count == 0) {
    $_SESSION['userprincipalname'] = $userprincipalname;
    $_SESSION['email'] = $email;
    if(!Azure::checkAccess($userprincipalname)) {
	 $_SESSION = array();
        session_destroy();
        echo Utils::render(
            'error_page.html', 
            [
                // layout
                'narrow' => true, 
                'hide_logout' => true,
                'PUBLIC_SERVICE' => defined('PUBLIC_SERVICE') ? PUBLIC_SERVICE : false,
                'header' => 'Access denied',
                'text' => 'Please contact your system administrator'
            ]
        );
        Utils::err("User Does Not Exist In Azure Group");
        exit();
    }

    Utils::showCreateUserPage();
    exit();
} 
Utils::err("userprincipalname $userprincipalname already exists");

Utils::messagePage("Error SSO 85", "<p>Please contact your system administrator</p>", true);




/*

//$url = https://graph.microsoft.com/v1.0/users/6e7b768e-07e2-4810-8459-485f84f8f204/memberOf

try {
    $token = json_decode($guzzle->get($url, [
        'form_params' => [
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'code' => $code,
            'grant_type' => 'authorization_code',
            'redirect_uri' => 'https://' . $_SERVER['HTTP_HOST'] . '/oauth-callback.php'
//            'scope' => 'https://graph.microsoft.com/.default',
        ],
    ])->getBody()->getContents());
} catch (Exception $e) {
    Utils::err('Exception');
    Utils::err($e->getMessage());
    print($e->getMessage());
    exit();
}



GET https://graph.microsoft.com/v1.0/users/6e7b768e-07e2-4810-8459-485f84f8f204/memberOf

*/



/*
function generateCodeVerifier($length = 128) {
    return bin2hex(random_bytes($length / 2));
}

function generateCodeChallenge($codeVerifier) {
    $hashed = hash('sha256', $codeVerifier, true);
    return rtrim(strtr(base64_encode($hashed), '+/', '-_'), '=');
}

$codeVerifier = generateCodeVerifier();
$codeChallenge = generateCodeChallenge($codeVerifier);

echo "Code Verifier: " . $codeVerifier . "\n";
echo "Code Challenge: " . $codeChallenge . "\n";
?>
*/
