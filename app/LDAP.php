<?php

/**
 * LDAP.php
 *
 * PHP version 7
 *
 * @category  Password_Manager
 * @package   PassHub
 * @author    Mikhail Vysogorets <m.vysogorets@wwpass.com>
 * @copyright 2016-2026 WWPass
 * @license   http://opensource.org/licenses/mit-license.php The MIT License
 */


namespace PassHub;

class LDAP 
{

    private static function isGoogleWorkspace() {
        if(isset(LDAP['url'])  && str_contains(strtolower(LDAP['url']), 'ldap.google.com')) {
            return true;
        }
        return false;
    }

    /**
     * Convert LDAP Base DN to dot-separated domain format
     * Example: "OU=Users,DC=company,DC=com" -> "company.com"
     * Example: "DC=example,DC=org" -> "example.org"
     * 
     * @param string $baseDn LDAP base DN in attribute-value format
     * @param bool $includeOU Whether to include OU components (default: false)
     * @return string Dot-separated domain format
     */
    static function baseDnToDomain($baseDn, $includeOU = false) {
        if (empty($baseDn)) {
            return '';
        }

        // Split by comma and trim whitespace
        $components = array_map('trim', explode(',', $baseDn));
        $dcParts = [];
        $ouParts = [];
        
        foreach ($components as $component) {
            // Check if it's a DC (Domain Component)
            if (preg_match('/^DC=(.+)$/i', $component, $matches)) {
                $dcParts[] = $matches[1];
            }
            // Check if it's an OU (Organizational Unit) and includeOU is true
            elseif ($includeOU && preg_match('/^OU=(.+)$/i', $component, $matches)) {
                $ouParts[] = $matches[1];
            }
        }
        
        // Combine parts (OU first, then DC)
        $allParts = array_merge($ouParts, $dcParts);
        
        return implode('.', $allParts);
    }

    public static function getMailDomains() {

        $mail_domains = [];

        if(is_array(LDAP['base_dn'])) {
            foreach(LDAP['base_dn'] as $base_dn) {
                array_push($mail_domains, self::baseDnToDomain($base_dn));
            }
        } else {
            $mail_domains = [LDAP['domain']];
        }        
        return $mail_domains;
    } 

    public static function connect() {


        $certs_found = false;

        if(isset(LDAP['LDAP_OPT_X_TLS_KEYFILE'])) {
            if(!is_readable(LDAP['LDAP_OPT_X_TLS_KEYFILE'])) {
                Utils::err("file " . LDAP['LDAP_OPT_X_TLS_KEYFILE'] . " is not readable");
            } else {
                Utils::err("Setting LDAP_OPT_X_TLS_KEYFILE to " . LDAP['LDAP_OPT_X_TLS_KEYFILE']);
                ldap_set_option(NULL, LDAP_OPT_X_TLS_KEYFILE, LDAP['LDAP_OPT_X_TLS_KEYFILE']);

                if(isset(LDAP['LDAP_OPT_X_TLS_CERTFILE'])) {
                    if(!is_readable(LDAP['LDAP_OPT_X_TLS_CERTFILE'])) {
                        Utils::err("file " . LDAP['LDAP_OPT_X_TLS_CERTFILE'] . " is not readable");
                    } else {
                        Utils::err("Setting LDAP_OPT_X_TLS_CERTFILE to " . LDAP['LDAP_OPT_X_TLS_CERTFILE']);
                        ldap_set_option(NULL, LDAP_OPT_X_TLS_CERTFILE, LDAP['LDAP_OPT_X_TLS_CERTFILE']);
                        $certs_found = false;
                    }
                }        
            }
        }

        if(isset(LDAP['LDAP_OPT_X_TLS_REQUIRE_CERT'])) {
            ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP['LDAP_OPT_X_TLS_REQUIRE_CERT']);
        } else {
            ldap_set_option(null, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_NEVER);
        }

        $ds=ldap_connect(LDAP['url']);
        if(!$ds) {
            Utils::err(" error 1070 ldapConnect fail");
            return false;
        }
    
        ldap_set_option($ds, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ds, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($ds, LDAP_OPT_NETWORK_TIMEOUT, 10);
        
        $r=ldap_bind($ds, LDAP['bind_dn'], LDAP['bind_pwd']);

        if (!$r) {
            $result =  "Bind error " . ldap_error($ds) . " " . ldap_errno($ds);
            Utils::err($result);
            $e = ldap_errno($ds); 
            ldap_close($ds);
            return false;
        } 
        return $ds;
    }

    private static function isInAdminGroup($user) {
        if (!isset($user['memberOf']['count'])) {
            return false;
        }
        $group_count = $user['memberOf']['count'];
        for($g = 0; $g < $group_count; $g++ ) {
            if($user['memberOf'][strval($g)] == LDAP['admin_group']) {
                return true;
            }
        }
        return false;
    }

    public static function getUsers() {
        $ds=LDAP::connect();

        if (!$ds) {
            return false;
        }

        if (self::isGoogleWorkspace()) {
            $user_filter = "(objectClass=person)";
        } else {
            $user_filter = "(objectClass=user)";
        }

        $group_filter="";
        if(is_array(LDAP['group'])) {
            foreach(LDAP['group'] as $group) {
                $group_filter .= "(memberOf={$group})";
            }
            $group_filter = "(|{$group_filter})";

        } else {
            $group_filter = "(memberOf=".LDAP['group'].")";
        }

/*

        (|(memberOf=CN=GroupA,OU=Groups,DC=example,DC=com)
  (memberOf=CN=GroupB,OU=Groups,DC=example,DC=com))
*/
        
        $ldap_filter = "(&{$user_filter}{$group_filter})";

        Utils::err('ldap_filter {$ldap_filter}');
        
        // Handle multiple base DNs
        $all_entries = [];
        if (is_array(LDAP['base_dn'])) {
            foreach (LDAP['base_dn'] as $base_dn) {
                $sr = ldap_search($ds, $base_dn, $ldap_filter);
                if ($sr === false) {
                    Utils::err("ldap_search fail, ldap_errno " . ldap_errno($ds) . " base_dn * " . $base_dn . " * ldap_filter " . $ldap_filter);
                    continue;
                }
                $entries = ldap_get_entries($ds, $sr);
                if ($entries && $entries['count'] > 0) {
                    // Merge entries (skip the 'count' key for now)
                    for ($i = 0; $i < $entries['count']; $i++) {
                        $all_entries[] = $entries[$i];
                    }
                }
                ldap_free_result($sr);
            }
            // Create a structure similar to ldap_get_entries return format
            $info = $all_entries;
            $info['count'] = count($all_entries);
            // Re-index numerically
            for ($i = 0; $i < count($all_entries); $i++) {
                $info[$i] = $all_entries[$i];
            }
        } else {
            $sr = ldap_search($ds, LDAP['base_dn'], $ldap_filter);
            if ($sr === false) {
                Utils::err("ldap_search fail, ldap_errno " . ldap_errno($ds) . " base_dn * " . LDAP['base_dn'] . " * ldap_filter " . $ldap_filter);
            }
            $info = ldap_get_entries($ds, $sr);
            if ($sr) {
                ldap_free_result($sr);
            }
        }

        Utils::err($info);

        $user_count = $info['count'];
        $user_upns = [];
        $admin_upns = [];

        for($u = 0; $u < $user_count; $u++) {
            $user = $info[strval($u)];

            Utils::err("user");
            Utils::err($user);

            
            if (self::isGoogleWorkspace()) {
                // Google Workspace uses 'mail' attribute or construct from 'uid'
                $upn = isset($user['mail']['0']) ? strtolower($user['mail']['0']) : 
                       (isset($user['uid']['0']) ? strtolower($user['uid']['0']) : '');
            } else {
                // Active Directory uses 'userprincipalname'
                $upn = strtolower($user['userprincipalname']['0']);
            }
            
            if (!empty($upn)) {
                array_push($user_upns, $upn);
                if(self::isInAdminGroup($user)) {
                    array_push($admin_upns, $upn);  
                }
            }
        }
        ldap_close($ds);
        Utils::err(["user_upns" => $user_upns, "admin_upns" => $admin_upns]);
        return ["user_upns" => $user_upns, "admin_upns" => $admin_upns];
    }

    public static function checkAccess($userprincipalname) {

        $ds=LDAP::connect();

        if (!$ds) {
            return false;
        }

        $user_filter = "(userprincipalname={$userprincipalname})";
        if (self::isGoogleWorkspace()) {
           $username = explode('@', $userprincipalname)[0]; 
           $user_filter = "(uid=$username)";

           // $user_filter = "(uid=marina)";
        }        



        $group_filter = "(memberOf=".LDAP['group'].")";
      
        $ldap_filter = "(&{$user_filter}{$group_filter})";
        
        // Handle multiple base DNs
        $user_enabled = 0;
        $info = ['count' => 0];
        
        if (is_array(LDAP['base_dn'])) {
            foreach (LDAP['base_dn'] as $base_dn) {
                $search_result = ldap_search($ds, $base_dn, $ldap_filter);
                if ($search_result === false) {
                    Utils::err("ldap_search fail, ldap_errno " . ldap_errno($ds) . " base_dn * " . $base_dn . " * ldap_filter " . $ldap_filter);
                    continue;
                }
                $temp_info = ldap_get_entries($ds, $search_result);
                if ($temp_info && $temp_info['count'] > 0) {
                    $info = $temp_info; // Use the first found user
                    $user_enabled = $temp_info['count'];
                    ldap_free_result($search_result);
                    break; // Found the user, no need to search other base DNs
                }
                ldap_free_result($search_result);
            }
        } else {
            $search_result = ldap_search($ds, LDAP['base_dn'], $ldap_filter);
            if ($search_result === false) {
                Utils::err("ldap_search fail, ldap_errno " . ldap_errno($ds) . " base_dn * " . LDAP['base_dn'] . " * ldap_filter " . $ldap_filter);
            } else {
                $info = ldap_get_entries($ds, $search_result);
                $user_enabled = $info['count'];
                ldap_free_result($search_result);
            }
        }


        if (defined('LDAP') && (isset(LDAP['admin_group']))) {
#                Utils::err('info');
#                Utils::err($info);

#                Utils::err('memberOf');
            $memberOf =  $info['0']['memberOf'];

#                Utils::err($memberOf);

            $group_count = $memberOf['count'];
            Utils::err('group count ' . $group_count);
            for( $i = 0; $i < $group_count; $i++) {
                $group = $memberOf[strval($i)];
#                    Utils::err('group ' . $i . ' ' . $group);
                if($group == LDAP['admin_group']) {
                    Utils::err('admin group member');
                    $_SESSION['admin'] = true;
                    break;
                }
            }
        }
        ldap_close($ds);
        if ($user_enabled) {
            return true;
        }
        Utils::err('Ldap: access denied');
        return false;
    }
}
