<?php

/**
 * login.php
 *
 * PHP version 7
 *
 * @category  Password_Manager
 * @package   PassHub
 * @author    Mikhail Vysogorets <m.vysogorets@wwpass.com>
 * @copyright 2016-2018 WWPass
 * @license   http://opensource.org/licenses/mit-license.php The MIT License
 */

require_once 'config/config.php';

if (!file_exists(WWPASS_KEY_FILE)) {
    Utils::err();
    die('Message to sysadmin: <p>Please set <b>config/config.php/WWPASS_KEY_FILE</b> parameter: file does not exist</p>');
}
if (!file_exists(WWPASS_CERT_FILE)) {
    die('Message to sysadmin: <p>Please set <b>config/config.php/WWPASS_CERT_FILE</b> parameter: file does not exist</p>');
}

if (!file_exists('vendor/autoload.php')) {
    die('Message to sysadmin: <p>Please run <b> sudo composer install</b> in the site root</p>');
}

require_once 'vendor/autoload.php';

use PassHub\Utils;
use PassHub\DB;
use PassHub\Puid;
use PassHub\Csrf;

$mng = DB::Connection();

session_start();

$_SESSION = array();
session_destroy();

session_start();

if (!isset($_SERVER['HTTP_USER_AGENT'])) {
    $_SERVER['HTTP_USER_AGENT'] = "undefined";
    Utils::err("HTTP_USER_AGENT undefined (corrected)");
}

$incompatible_browser = false;
$h1_text = "Sorry, your browser is no longer supported";
$advise = "Please try another browser, e.g. Chrome or Firefox";

// Safari version 9 on Mac
if (preg_match('/.*Macintosh.*Version\/9.*Safari/', $_SERVER['HTTP_USER_AGENT'], $matches)) {
    $isMacintosh = "Macintosh";
    $incompatible_browser = "Safari";
    $h1_text = "Sorry, your version of Safari browser is too old and no longer supported";
    $advise = "Please upgrade MAC OS X (or Safari) or install Chrome or Firefox browsers";
}

// iOS 9 and lower
if (stripos($_SERVER['HTTP_USER_AGENT'], "iPhone")) {
    $iOS = "iPhone";
} else if (stripos($_SERVER['HTTP_USER_AGENT'], "iPad")) {
    $iOS = "iPad";
} else if (stripos($_SERVER['HTTP_USER_AGENT'], "iPod")) {
    $iOS = "iPod";
} else {
    $iOS = false;
}

if ($iOS) {
    $user_agent = explode(' ', $_SERVER['HTTP_USER_AGENT']);
    $idx = array_search('OS', $user_agent);
    $ios_version = $user_agent[$idx+1];
    if (substr($ios_version, 0, 1) != "1") {
        $incompatible_browser = "iOS";
    }
    $h1_text = "Sorry, older verions of $iOS browsers are no longer supported";
    $advise = "Still you can open PassHub in a desktop or a laptop browser and scan the QR code with WWPass Key app on your $iOS";
}

// IE
if (stripos($_SERVER['HTTP_USER_AGENT'], "Trident")) {
    $incompatible_browser = "IE";
    $h1_text = "Sorry, Internet Explorer is no longer supported";
    $advise = "Please use Chrome, Firefox or Edge browsers";
}

if ($incompatible_browser) {
    session_destroy();
    Utils::err("incompatible browser " . $_SERVER['HTTP_USER_AGENT']);

    echo Utils::render(
        'notsupported.html',
        [
            'hide_logout' => true,
            'narrow' => true,
            'PUBLIC_SERVICE' => defined('PUBLIC_SERVICE'), 
            'h1_text'=> $h1_text,
            'advise' => $advise,
            'incompatible_browser' => $incompatible_browser,
            'iOS_device' => $iOS
        ]
    );
    exit();
}

/*
if (defined('MAIL_DOMAIN') && isset($_GET['reg_code'])) {
    passhub_err("session clean2");
    $_SESSION = [];
    $_SESSION['reg_code'] = $_GET['reg_code'];
    passhub_err("login rc " . print_r($_SESSION, true));
    echo theTwig()->render(
        'login_reg.html',
        [
            'narrow' => true,
            'hide_logout' => true,
            'PUBLIC_SERVICE'=> defined('PUBLIC_SERVICE')
        ]
    );
    exit();
}
*/

if (defined('MAIL_DOMAIN') && isset($_GET['reg_code'])) {
    $_SESSION = [];
    $status = Puid::processRegCode1($mng, $_GET['reg_code']);

    if ($status !== "Ok") {
        Utils::err("reg_code: " . $status);
        Utils::errorPage($status);
    }
    echo Utils::render(
        'login_reg.html',
        [
            'narrow' => true,
            'hide_logout' => true,
            'PUBLIC_SERVICE'=> defined('PUBLIC_SERVICE')
        ]
    );
    exit();
} 
if (defined('MAIL_DOMAIN') && isset($_GET['changemail'])) {
    $_SESSION = [];
    $status = Puid::processRegCode1($mng, $_GET['changemail'], "change");

    if ($status !== "Ok") {
        Utils::err("reg_code: " . $status);
        Utils::errorPage($status);
    }
    echo Utils::render(
        'login_reg.html',
        [
            'narrow' => true,
            'hide_logout' => true,
            'PUBLIC_SERVICE'=> defined('PUBLIC_SERVICE'),
            'change' => true
        ]
    );
    exit();
} 

if (isset($_SESSION['PUID'])) {
    header("Location: index.php");
    exit();
}

if (!isset($_GET['wwp_status'])) {
    unset($_SESSION['reg_code']);
}

if (array_key_exists('wwp_status', $_REQUEST) && ( $_REQUEST['wwp_status'] != 200)) {
    $_SESSION = [];
    Utils::err("wwp_status: " . print_r($_REQUEST, true));
} else if (array_key_exists('wwp_ticket', $_REQUEST)) {
    if ((strpos($_REQUEST['wwp_ticket'], ':c:') == false) 
        && (strpos($_REQUEST['wwp_ticket'], ':pc:') == false) 
        && (strpos($_REQUEST['wwp_ticket'], ':cp:') == false)
    ) {
        // do nothing
    } else {
        // clear all keys but req_code if present
        $_SESSION = array_intersect_key($_SESSION, array('reg_code' => ""));

        $ticket = $_REQUEST['wwp_ticket'];
        try {
            $test4 = (intval(explode('.', WWPass\Connection::VERSION)[0]) > 3);

            if ($test4) {
                $wwc = new WWPass\Connection(
                    ['key_file' => WWPASS_KEY_FILE, 
                    'cert_file' => WWPASS_CERT_FILE, 
                    'ca_file' => WWPASS_CA_FILE]
                );
                $new_ticket = $wwc->putTicket(
                    ['ticket' => $ticket,
                    'pin' =>  defined('WWPASS_PIN_REQUIRED') ? WWPASS_PIN_REQUIRED : false,
                    'client_key' => true,
                    'ttl' => WWPASS_TICKET_TTL]
                );

                $_SESSION['wwpass_ticket'] = $new_ticket['ticket'];
                $_SESSION['wwpass_ticket_renewal_time'] = time() + $new_ticket['ttl'] / 2;
                $puid = $wwc->getPUID(['ticket' => $ticket]);
                $puid = $puid['puid']; 
            } else { // version 3
                $wwc = new WWPass\Connection(WWPASS_KEY_FILE, WWPASS_CERT_FILE, WWPASS_CA_FILE);
                $new_ticket = $wwc->putTicket($ticket, WWPASS_TICKET_TTL, WWPASS_PIN_REQUIRED?'pc':'c');
                $_SESSION['wwpass_ticket'] = $new_ticket;
                $_SESSION['wwpass_ticket_renewal_time'] = time() + WWPASS_TICKET_TTL/2;
                $puid = $wwc->getPUID($ticket);
            }
            
            $_SESSION['PUID'] = $puid;

            $_SESSION['wwpass_ticket_creation_time'] = time();

            if (!isset($_REQUEST['wwp_hw'])) {
                $_SESSION['PasskeyLite'] = true;
            }
            $ip = $_SERVER['REMOTE_ADDR'];
            Utils::log("sign-in $puid $ip");


            $puid = new Puid($mng, $_SESSION['PUID']);

            $result = $puid->getUserByPuid();
            if($result['status'] == "not found") {

                if( /*defined('CREATE_USER')  && isset($_SESSION['CREATE_USER'] && */ !isset($_SESSION['UserID']) )   {
                    Utils::log("Create User CSE begin " . $_SERVER['REMOTE_ADDR'] . " " . $_SERVER['HTTP_USER_AGENT']);

                    $template_safes = file_get_contents('config/template.xml');
                    
                    if (strlen($template_safes) == 0) {
                        Utils::err("template.xml absent or empty");
                        Utils::errorPage("Internal error. Please come back later.");
                    } else {
                        $result = [
                            'status' => "not found", 
                            'ticket' => $_SESSION['wwpass_ticket'],
                            'template_safes' => json_encode($template_safes)
                        ];
                    }
                    
                    header('Cache-Control: no-cache, must-revalidate');
                    header('Expires: Mon, 01 Jan 1996 00:00:00 GMT');
                    header('Content-type: application/json');
                    
                    echo json_encode($result);
                    exit();
                }
            }

            if ($result['status'] == "Ok") {
                $UserID = $result['UserID'];
                $_SESSION["UserID"] = $UserID;
                $result = array("status" => "Ok");
                $csrf=Csrf::get();
                
                header('Cache-Control: no-cache, must-revalidate');
                header('Expires: Mon, 01 Jan 1996 00:00:00 GMT');
                header('Content-type: application/json');
                header('X-CSRF-TOKEN: ' . $csrf);
                echo json_encode($result);
                exit();
            }
            
            Utils::err('Hello20');
            exit($result['status']);//multiple PUID records;

            
            Utils::err(print_r($_SESSION, true));


            $result = array("status" => "Ok");
            $csrf=Csrf::get();
            
            header('Cache-Control: no-cache, must-revalidate');
            header('Expires: Mon, 01 Jan 1996 00:00:00 GMT');
            header('Content-type: application/json');
            header('X-CSRF-TOKEN: ' . $csrf);
            
            echo json_encode($result);
            exit();

        }  catch (Exception $e) {
            # $err_msg = $e->getMessage() . ". Please try again";
            Utils::err("wwp exception: " . $e->getMessage());
        }
    }
}
