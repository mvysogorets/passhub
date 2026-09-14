<?php


require_once 'config/config.php';
require_once 'vendor/autoload.php';

use PassHub\Utils;
use PassHub\Csrf;
use PassHub\DB;
use PassHub\User;

$mng = DB::Connection();

session_start();

$settingsInfo = SAML;

$auth = new \OneLogin\Saml2\Auth($settingsInfo);

if (isset($_GET['acs'])) {

    if (isset($_SESSION) && isset($_SESSION['AuthNRequestID'])) {
        $requestID = $_SESSION['AuthNRequestID'];
    } else {
        $requestID = null;
    }

    $auth->processResponse($requestID);

    $errors = $auth->getErrors();

    if (!empty($errors)) {
        echo '<p>',implode(', ', $errors),'</p>';
        if ($auth->getSettings()->isDebugActive()) {
            echo '<p>'.htmlentities($auth->getLastErrorReason()).'</p>';
        }
    }

    if (!$auth->isAuthenticated()) {
        echo "<p>Not authenticated</p>";
        exit();
    }

    $_SESSION['samlUserdata'] = $auth->getAttributes();
    $_SESSION['samlNameId'] = $auth->getNameId();
    $_SESSION['samlNameIdFormat'] = $auth->getNameIdFormat();
    $_SESSION['samlNameIdNameQualifier'] = $auth->getNameIdNameQualifier();
    $_SESSION['samlNameIdSPNameQualifier'] = $auth->getNameIdSPNameQualifier();
    $_SESSION['samlSessionIndex'] = $auth->getSessionIndex();

    Utils::err('Session');
    Utils::err($_SESSION);

    unset($_SESSION['AuthNRequestID']);
    if (isset($_POST['RelayState']) && \OneLogin\Saml2\Utils::getSelfURL() != $_POST['RelayState']) {
        // To avoid 'Open Redirect' attacks, before execute the 
        // redirection confirm the value of $_POST['RelayState'] is a // trusted URL.
        $auth->redirectTo($_POST['RelayState']);
    }
}
