---
sidebar_position: 11
---

# Installing PassHub on Linux

## About This Document

PassHub is a web-based password manager for individuals and teams with support for client-side encryption. PassHub relies on WWPass authentication and data encryption technology and can work both with hardware WWPass Key and WWPass Key smartphone application.


Practical knowledge of web server deployment is required, including DNS configuration and SSL certificates.

This installation guide was tested for Ubuntu 24.04 but will work with other Linux Distrubutions.

## Prerequisites

To deploy Passhub, you should set up a Linux Server and
configure a regular, non-root user with `sudo` privileges. The following hardware requirements should be met:

- CPU: 1 Core
- RAM: 2 GB
- Storage: 30 GB (SSD is preferred, but optional)

These requirements may need to be adjusted depending on the number
of PassHub users.

Your server should be accessible either publicly or within your organization network and have a DNS name configured. An internet connection is needed both for the purposes of this guide and regular operation. A valid (not self-signed) SSL certificate is required so that your server can be accessed via HTTPS.

## Step 1: Install the Nginx Web Server

Since this is our first interaction with the apt packaging system in this session, we should update our local package index, so that we have access to the most recent versions of packages. After that, Nginx can be installed.

```bash
sudo apt update
sudo apt install -y nginx
```

On most Linux Systems, Nginx is configured to start running upon installation.

## Step 2: Install MongoDB Database

While it is possible to use the MongoDB version which comes with some Linux Distrubutions, we highly recommend MongoDB version 7.0.

Please follow instructions on MongoDB site: https://www.mongodb.com/docs/manual/administration/install-on-linux/#std-label-install-mdb-community-edition-linux

Specifically for Ubuntu 24.04 use
https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/#std-label-install-mdb-community-ubuntu

**Note:** The current command that MongoDB provides for pulling the list file for Ubuntu 24.04 is incorrect and must be changed to:
```bash
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu/dists/jammy/mongodb-org/7.0/multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
```

## Step 3: Install PHP

PHP might be installed on your Linux System, However for the latest MongoDB version we suggest PHP Version 8.3.

Type the following command to install PHP and other additional modules required by PassHub:

```bash
sudo apt install -y php php-dev php-fpm php-curl php-mbstring php-mail php-pear php-net-smtp php-ldap
```

### 3.1: Maximum upload size

Increase maximum upload size limits in `/etc/php/8.3/fpm/php.ini`:

```
post_max_size = 30M
upload_max_filesize = 30M
memory_limit = 256M
```

### 3.2: MongoDB driver

Install the verision 1.19 MongoDB PHP driver with PECL, according to the MongoDB instructions: https://docs.mongodb.com/php-library/current/tutorial/install-php-library/

**Note:** Do Not Run PHP Composer as we will do that later

You may check the installed module version with the CLI command

```php
php -r 'echo phpversion("mongodb");'
```

Make sure that the MongoDB module has been added to `php.ini` as it does not automatically always take effect

```
extension=mongodb.so
```
Finally, restart **php8.3-fpm** so that your configuration changes take effect:

```bash
sudo service php8.3-fpm restart
```

### 3.4: Install PHP Composer

Most Linux distrubutions come with PHP Composer Version 2.7, to check run:

```bash
composer -vvv about
```
If not installed run:

```bash
sudo apt install composer
```

## Step 4: Extract PassHub Files

Grab the latest release of Passhub for Business from: https://github.com/wwpass/passhub/releases

Untar the passhub.business.240829.tar.gz archive and put it in your server home directory.

Extract the contents of the archive into the `/var/www` directory:

```bash
cd /var/www
sudo tar xvzf ~/passhub.business.240829.tgz
```

Change the ownership of the extracted directory:

```bash
sudo chown -R www-data:www-data /var/www/passhub
```

### 4.1 Install PHP libraries

In the _/var/www/passhub_ directory run composer:

```bash
sudo composer install
sudo composer update
composer require mongodb/mongodb
```
**Note:** If these fail you can append '--ignore-platform-reqs'


### 4.2 Create working directories

Create PassHub log, and working directories:

```bash
sudo mkdir /var/log/passhub
sudo chown www-data:www-data /var/log/passhub
sudo mkdir /var/lib/passhub
sudo chown www-data:www-data /var/lib/passhub
```

## Step 5: Configure Nginx Server

To configure Nginx web server, we need to obtain two SSL certificates: first, the HTTPS certificate to protect web connection and second - WWPass Service Provider certificate for PassHub.

Final Nginx configuration depends on many factors, particularly if the PassHub is the only service or if there are more than one already existing URLs served by Nginx. If PassHub is not the first destination, you are probably already experienced enough to adapt following instructions to your needs.

Here are the steps for a freshly installed Nginx.

### 5.1 PassHub URL

Start with selecting a URL for the PassHub service, e.g. 'passhub.yourcompany.com'. Set your DNS accordingly.

### 5.2 WWPass certificates

PassHub requires a WWPass Service Provider certificate, which can be obtained at the [WWPass developer](https://developers.wwpass.com) site. Click on 'Native Integrations', then 'Add New Application' and follow the instructions.

### 5.3 SSL certificates

Obtain the SSL certificate from Certificate Authority of your choice, e.g. [Let's Encrypt CA](https://letsencrypt.org/).

### 5.4 Nginx configuration

There are no specific requirements for the nginx configuration. You will create a new configuration under:
```bash
/etc/nginx/sites-available/exampleconfig 
```
Here is an example config:
```nginx
server {
  listen 80;
  listen [::]:80;
  server_name example.com;
  location / {
    rewrite ^(.*)$ https://passhub.yourcompany.com$1;        # Note 1
  }
}
server {
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name passhub.yourcompany.com;    
  ssl on;
  ssl_certificate /path/to/ssl/certificate/fullchain.pem;    # Note 2
  ssl_certificate_key /path/to/ssl/certificate/privkey.pem;  
  client_max_body_size 30M;
  root /var/www/passhub.business.240829;   
  index index.php index.html index.htm;                      # Note 3
  location ~/(config|helpers|src) {
    deny all;
    return 404;
  }
  location ~ \.php$ {                                        # Note 4
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php8.3-fpm.sock; 
  }
}
```

**Notes**:

1. Change `passhub.yourcompany.com` to the DNS name of your server;
2. Make sure `ssl_certificate` and `ssl_certificate_key` point to existing SSL certificate files; 
3. Add `index.php` to the `index index.html;` module if not in config file
4. Everything inside the location module is required to connect and run PHP for Passhub 

Create a symbolic link in the `/etc/nginx/sites-enabled/`
directory so that Nginx can pick up the configuration file we just created:

```bash
sudo ln -s /etc/nginx/sites-available/passhub.conf /etc/nginx/sites-enabled/passhub.conf
```

Check the Nginx configuration for possible errors:

```bash
sudo nginx -t
```

If everything is correct, you will see the following output:

```sh
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

If Nginx reports configuration errors and you see output like this:

```sh
nginx: configuration file /etc/nginx/nginx.conf test failed
```

Revise your Nginx configuration and re-test.

Once your Nginx configuration contains no errors, reload nginx with new configuration data:

```bash
sudo nginx -s reload
```

**Optional Tip**: If you need to temporarily disable your PassHub instance in Nginx, remove the symbolic link in the `/etc/nginx/sites-enabled/`
directory and reload Nginx configuration like this:

```bash
sudo rm /etc/nginx/sites-enabled/passhub.conf
sudo nginx -s reload
```

To re-enable Nginx, just re-create the symbolic link and reload Nginx configuration:

```bash
sudo ln -s /etc/nginx/sites-available/passhub.conf /etc/nginx/sites-enabled/passhub.conf
sudo nginx -s reload
```

## Step 6: Adjust PassHub Configuration

Create a new PassHub configuration using the sample configuration file bundled with the PassHub distribution.

Create a new configuration file by copying `config-sample.php`:

```bash
sudo cp /var/www/passhub/config/config-sample.php /var/www/passhub/config/config.php
```

And open it in a text editor:

```bash
sudo nano /var/www/passhub/config/config.php
```

The configuration file has the following content by default:

```php
<?php

// Path to your WWPass service provider CRT and KEY files.
define('WWPASS_CERT_FILE', "/etc/ssl/yourcompany.com.crt");
define('WWPASS_KEY_FILE', "/etc/ssl/yourcompany.com.key");

// Path to the WWPass certificate authority file.
define('WWPASS_CA_FILE', "config/wwpass_sp_ca.crt");

// Session expiration timeout in seconds, prolonged automatically by user activity.
define('WWPASS_TICKET_TTL', 1200);

// Set to true to request PIN or biometrics each time user signs in, set to false otherwise.
define('WWPASS_PIN_REQUIRED', true);

// Log out on hardware WWPass Key removal, default true
define('WWPASS_LOGOUT_ON_KEY_REMOVAL', true);

// MAX allocated resources, storage size in bytes
define('MAX_RECORDS_PER_USER', 10000);
define('MAX_STORAGE_PER_USER', 1024 * 1024 * 1024);

// Some upper limits
define('MAX_SAFENAME_LENGTH', 20);
define('MAX_FILENAME_LENGTH', 40);
define('MAX_URL_LENGTH', 2048);
define('MAX_NOTES_SIZE', 2000);

// User inactivity reminder, set to 9 min. After another minute (total 10 minutes) a user will be logged out automatically
define('IDLE_TIMEOUT', 540);

// logs are written to the dedicated files in LOG_DIR or to SYSLOG service or both
// Path to PassHub log directory
define('LOG_DIR', '/var/log/passhub');

define('SYSLOG', true);

// ** Database **

// Database name
define('DB_NAME', 'passhub');
// Mongodb connection line (unsafe!)
define('MONGODB_CONNECTION_LINE', 'mongodb://localhost');

//Example connection line with username, password, and non-default port
//define('MONGODB_CONNECTION_LINE', "mongodb://username:password@localhost:port");

//Example connection line for distributed Mongodb.
//define('MONGODB_CONNECTION_LINE', "mongodb://username:password@phub-srv1:port,phub-srv2:port,phub-arbiter:port/phub?replicaSet=rsphub&ssl=true");


// ** FILE storage** all sizes in Bytes
define('MAX_FILE_SIZE', 5 * 1024 * 1024);

// local file storage: FILE_DIR should be created in advance
define('FILE_DIR', '/var/lib/passhub');

// or, S3-compatible file storage:
/*
define(
  'S3_CONFIG', [
      'version' => 'latest',
      'region'  => 'sfo2',
      'endpoint' => 'https://sfo2.digitaloceanspaces.com',
      'credentials' => [
          'key'    => 'some_key',
          'secret' => 'some_secret',
      ],
  ]
);
define('S3_BUCKET', 'phub');
*/

// or,Google drive
//define('GOOGLE_CREDS', 'google_drive_credentials.json');

// ** Mail **

// Email address to handle end-user support requests.
define('SUPPORT_MAIL_ADDRESS', 'support@yourcompany.com');

// local SMTP on Unix server, sendmail_from defaults to noreply@<host domain name>
// to override the setting:
define('SENDMAIL_FROM', "noreply@yourcompany.com");

//  or, mail client of the external server, requires  "sudo apt install php-mail"
/*
define(
    'SMTP_SERVER', [
      'host' => 'ssl://smtp.gmail.com',
      'port' => '465',
      'auth' => true,
      'username' => 'mycompanylazymail@gmail.com',
      'password' => 'ppppp'
    ]
);
*/

// ** Access control and sharing method

// If LDAP is defined, it has 2nd highest priority

/*
define(
    'LDAP', [
      // Active directory server schema, name and port
      'url' => 'ldaps://ad.xxxx.lan:636',

      'base_dn' => "ou=office,dc=xxxx, dc=lan",

      // When creating new user account, Passhub identifies a user by UserPrincipal name, which consists of user name (logon name), separator (the @ symbol), and domain name (UPN suffix). In case the user provides only username, without @-symbol and domain, the `domain` parameter is added to obtain UPN

      'domain' => "xxxx.lan",

      // Group, which allows to access PassHub:
      'group' => "CN=Passhub Users,OU=Groups,OU=Office,DC=xxxx,DC=lan",

      // cerdentials used by Passhub itself when cheking user membership to the above group
      'bind_dn' => "cn=xxxxx,ou=xxxxx,dc=wwpass,dc=lan",
      'bind_pwd' => "xxxxx"
    ]
);
*/

// Azure & EntraID Definition, has the highest priority

/*
define(
    'AZURE', [

    // App Registration ID's
    'application_client_id' => "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    'directory_tenant_id' => "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",

    // App Registration Client Secret
    'client_value' => "XXXXX~XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",

    // Name of Groups in Entra ID
    'user_group' => "PasshubUsers",
    'admin_group' => "PasshubAdmins",
    ]
);
*/

// if LDAP is not defined: allowed mail domains, space seperated. 
// The user will be assigned admin priviledges on the first login

define('MAIL_DOMAIN', "admin@yourcompany.com");

// or use your mail only to start
// define('MAIL_DOMAIN', "you@yourcompany.com");
// 
// define('MAIL_DOMAIN', "any");

// Sharing invitation expiration timeout, default 48 hours (anonymous accounts only)
define('SHARING_CODE_TTL', 48*60*60);

// **

// white-label login page
// define('LOGIN_PAGE', "views/login.html");
```

Perform the following adjustments:

1. Set `WWPASS_CERT_FILE` to the absolute path to your WWPass Service Provider certificate file (eg. /etc/ssl/yourcompany.com.crt);
2. Set `WWPASS_KEY_FILE` to the absolute path to your WWPass Service Provider key file (e.g. /etc/ssl/yourcompany.com.key);

3. Set `SUPPORT_MAIL_ADDRESS` to an email address you are going to use for handling user support requests;

Additionally, you may want to adjust the `WWPASS_PIN_REQUIRED` parameter, which controls whether PassHub should request PIN during authentication. Set it to `false` if you want to disable PIN requests, leave the default `true` value otherwise.

Save and close the file when you are finished.

## Step 7: Setting up email

Passhub uses email service for feedback messages and user email address verification. Setting up a full-featured modern email server may be a tricky task. Depending on your resources, choose one out of the three options to configure PassHub mail.

### Option 1. Mail server on the same computer where PassHub is running

If you have one, you are all set: Passhub uses it by default.

### Option 2

Create or use a dedicated mail account on your company mail server such as 
[MailJet](https://www.mailjet.com/).
Now add the account data to the config.php file, for example:

```php
 define(
    'SMTP_SERVER', [
      'host' => 'ssl://your.mail.server.com',
      'port' => '465',
      'auth' => true,
      'username' => 'passhub@your.mail.server.com',
      'password' => 'dedicated_account_password'
    ]
);
```

### Option 3

Create a dedicated gmail account. Basically, it is a variant of **Option 2**.

Add account data to the config.php, for example

```php
 define(
    'SMTP_SERVER', [
      'host' => 'ssl://smtp.gmail.com',
      'port' => '465',
      'auth' => true,
      'username' => 'dedicated_account@gmail.com',
      'password' => 'dedicated_account_password'
    ]
);
```

For Gmail, tweak the security settings of the account. In the account settings choose 'Security' and turn on **Less secure app access** switch

**Note:** Add or remove fields when required for mail setup

## Step 8: Test PassHub

Open your web browser and navigate to the address of your PassHub server.  
e.g: `'passhub.yourcompany.com'`. You should see the PassHub main page with the authentication QR code. 

**Note:** If your computer has the WWPass Security Pack installed, you will also see a button to log in with the hardware WWPass Key under the QR code.

## Step 9: Site administrator

For corporate use, a PassHub administrator should be assigned. The administrator has the rights to monitor user activities, delete users or grant the PassHub administrator role to other users. The PassHub administrator also controls the white list of email addresses of external users allowed to create an account.

The first logged-in user who logins to the site is granted site administrator rights automatically. Other users only become site administrators by permission of the existing site administrators.

## Advanced: store your encrypted files in the cloud

It is well possible to keep all your encrypted files in the Amazon S3 compatible object storage service. This way, you increase the availability of your data and simplify storage configuration for distributed deployments of PassHub.

The good news is that Amason S3 API becomes a standard de-facto, and the same code works for many object storage providers, like Google Cloud Platform, Digital Ocean Spaces, Vultr, and Linode.

With `s3fs` solution, available for Linux, it is also possible just to mount S3-compatible storage to the filesystem, as if it was an NFS external storage. This way you do not need to write a single line of code.

PassHub supports S3-compatible storage. To configure this option, create an Object storage account in one of the cloud service providers and change the config file:

```php
// Comment out other storage methods
// define('FILE_DIR', '/var/lib/passhub');

// Provide S3 account data, like that for example

define(
    'S3_CONFIG', [
        'version' => 'latest',
        'region'  => 'sfo2',
        'endpoint' => 'https://sfo2.digitaloceanspaces.com',
        'credentials' => [
            'key'    => 'kkkkkkkkk',
            'secret' => 'ssssssssss',
        ],
    ]
);
define('S3_BUCKET', 'phub');
```

## More on user registration and sharing of safes

### Anonymous

By default, when a user logs into PassHub for the first time, a new account is created. There are no preconditions and no user information is gathered. Hence, when a safe owner shares a safe, there is no way to identify the recipient. The resulting process is three-step:

1.  The owner gets a sharing code and sends it to the recipient by email, or using any messenger

2.  The recipient fills in the "Accept sharing" dialog with the sharing code and a safe name of their own choice

3.  The safe owner confirms sharing

The only optional parameter for this configuration in the `config.php` file is `SHARING_CODE_TTL` which defaults to 48 hours

### Mail or email domain

If the parameter `MAIL_DOMAIN` is set in the `config.php` file, new users are required to provide and verify their email address. Now, when sharing safes, the recipient is identified by the email address thus reducing sharing procedure to a single step. The very parameter `MAIL_DOMAIN` defines initial limitations on acceptable email addresses. In its basic form, the parameter contains the email domain of the company, thus restricting possible PassHub users. For example, if the corporate email address looks like `somebody@company.com`, set

MAIL_DOMAIN = "company.com"

Alternatively, MAIL_DOMAIN may be set to a single predefined email address

MAIL_DOMAIN = "adm@company.com"

then only this person will be allowed to create a PassHub account. Typically this email address belongs to PassHub administrator, who can, later on, invite other users.

Finally, the setting

MAIL_DOMAIN = "any"

implies no limitations on users' email address. New users still are requested to provide and verify their email.

### LDAP

PassHub may be connected to the corporate Active Directory. This time when users logs in for the first time, their Active Directory credentials, username (upn actually) and passwords are requested and verified against AD service.

Next, the user email, stored in Active Directory is obtained and the user membership in a predefined group is checked. The group membership means the user is allowed to access PassHub.
Later, the group membership is checked every time the user logs in to PassHub.

To configure PassHub connection to Active Directory, fill the LDAP structure in the `config.php` file. When `LDAP` parameter is set, it takes precedence over `MAIL_DOMAIN` or Anonymous settings

For detailed LDAP parameters see the file `config-sample.php` in the distro and in the text above.

## Getting bigger

### Speed up MongoDB

When the database grows enough to slow down PassHub operations, collection indexing significatly improves PassHub responce times.

With `mongo` shell console, create indexes as follows:

```
db.safe_items.createIndex({SafeID:-1})
db.safe_folders.createIndex({SafeID:-1})
```

### php-fpm bottleneck

The number of simultaneous php-fpm instances affects request processing.

Check `php8.3-fpm.log` files for the following lines:

```
WARNING: [pool www] server reached pm.max_children setting (5), consider raising it
```

In this case increase settings in `/etc/php/8.3/fpm/pool.d/www.conf`

```
pm.max_children = 10
pm.start_servers = 4
pm.min_spare_servers = 2
pm.max_spare_servers = 6
```

## Feedback and Support

Should you experience any difficulties during the installation of PassHub, please feel free to contact our support team at support@wwpass.com.
