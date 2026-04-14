## LDAP configuration

LDAP configuration is a block in the configure.php file with the following content:

```php
define(
    'LDAP', [
      // Active directory server schema, name and port
      'url' => 'ldaps://your-company-ldap-server.com:636',

    /*
        parameter base_dn is used in ldap_search() 
    */ 

      'base_dn' => "dc=yourcompany,dc=com",

    /*
      When creating new user account, Passhub identifies a user by UserPrincipal name,  which consists of user name (logon name), separator (the @ symbol), and domain name (UPN suffix). In case the user provides username only, without @-symbol and domain, the domain parameter is added to obtain UPN
    */
      'domain' => "yourcompany.com",

      /*
      User access rights are fully defined by the LDAP groups.

      To obltain user access rights, Passhub checks user memebership in two groups, "passhub users" and "passhub admin". 
      
      Only users of the "passhub user" group are allowed to create an account and to login to the Passhub.

      If, in addition, a user is a member of the "passhub admin"  group, the user is granted an admin rights
      Below is an example of how the groups are configured (NOTE: group names are arbitrary, you can use )
      */
     
      'group' => "cn=passhub-users,ou=Groups,dc=yourcompany,dc=com",
      'admin_group' => "cn=passhub-admin,ou=Groups,dc=yorcompany,dc=com",

      /* Credentials used by Passhub application as a client when cheking user membership to the above groups

      Depending on a paticular LDAP server configuration, the `Bind DN` paraneter may  be  in the form of Full Distinguished name: 

      uid=alice,ou=unit,dc=example,dc=c

      Or a user principal name:

      alice@yourcompany.com

      Or just a username

      alice
      */

      'bind_dn' => "alice",
      'bind_pwd' => "passweord1",

       /*
       OPTIONAL: client cetificates. Are required by some LDAP servers
       */ 
      'LDAP_OPT_X_TLS_KEYFILE' => "/etc/ssl/Google_2029_04_01_15386.key",
      'LDAP_OPT_X_TLS_CERTFILE' => "/etc/ssl/Google_2029_04_01_15386.crt",

       /*
       OPTIONAL. By default,  Passhub does not verify client certificates. To force the verification set
       */

      'LDAP_OPT_X_TLS_REQUIRE_CERT' => true;

      /*
      OPTIONAL: While LDAP provides its own user identification procedure, by setting this optional parameter to true one can use regular email verfication procedure, not related to LDAP
      */
      'mail_registration' => true

    ]
);
```



## Googe Workspace specific settings
 
1. Google LDAP does not provide any user authentication procedure. To use regular email verification, add the following line:

```
   'mail_registration' => true
```

2. Google Workspace issues self-signed client certificates, the latter triggers nodejs and python errors. For Passhub, the cert check procedure is disabled by default

2. When cheking group membership, Google does not use userprincipalname, instead the filter looks like that:

```
(&(uid=username)(memberof=cn=passhub-user-group,ou=Groups,dc=xxxx,dc=com))  
```
where the `username` is a part of th euser mail before @ character

Passhub detects Google workspace by LDAP url and behaves appropriately (thus making `mail_registration` setting redundant): 

```
'url' => 'ldaps://ldap.google.com:636'
```
