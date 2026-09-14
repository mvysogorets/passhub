<?php


namespace PassHub;

require_once 'config/config.php';
require_once 'vendor/autoload.php';

# use GuzzleHttp\Client;


# namespace PassHub;


class SAML
{
    public static function Authenticate() {

        $settingsInfo = SAML;
//        $baseurl = 'https://' .  $_SERVER['SERVER_NAME'];
//        $settingsInfo['baseurl'] = $baseurl;
//        $settingsInfo['assertionConsumerService'] = $baseurl . $settingsInfo['assertionConsumerService'];

        Utils::err("settingsInfo");
        Utils::err($settingsInfo);


        $auth = new \OneLogin\Saml2\Auth($settingsInfo);
        $auth->login();
    }
}