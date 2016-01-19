ColdAddress Bitcoin Address Generator
=====================================

This is a PHP web application for generating Bitcoin private ECDSA keys and related payment addresses that are not
under the control of a software wallet.

For full documentation on the web application including why someone *might* want to do such a thing, please see the
demonstration page hosted at <https://bitcoin.librelamp.com/address.php>

This README file strictly deals with installation of the web application in an Apache web server.

There is no technical reason why it will not run in other servers, but you are on your own for other servers.

Server Environment
------------------

This web application should not be run on a public web server. It is intended to be run on the local host and accessed
from a web browser running on the same local host.

### Remote Server
If you must run it on a web server that is on a different host than the web browser used to access it, you really should
take the following precautions:

* The server *must* only accept TLS connections. Preferably only TLS 1.2 or newer.
* The server *must* only support modern secure cipher suites.
* The server *should* only support ECDHE cipher suites.
* The server *must* use a valid Certificate Authority signed certificate.
* The server *should* use DNSSEC with a valid TLSA record.
* The server *must* require authentication. Apache basic authentication is probably the best choice.
* The client *should* validate TLSA records.

### Local Server
When running the server on the same host as the browser used to access it, TLS is not needed. However it needs to be
a host that is not accessible by random people. The web server should only be listening on `127.0.0.1` and/or `::1`

PHP Requirements
----------------

This web application has only been tested in PHP 5.6.x but it probably runs in older versions as well. I do not know
if the ECC stuff works in PHP 7 but I *suspect* it does.

The following PHP modules must be available:

* php-bcmath
* php-gmp
* php-xml

Malware Safety
--------------

The host should not have crapware like Oracle Java or Adobe Flash installed. This goes for both the server and the
host the web browser used to access the server if they are different.

The host should not have Google Chrome installed. Chrome bundles Adobe Flash and is therefore a vulnerable product.

I highly recommend running this under the GNU/Linux operating system or one of the BSD Unix variants.

Do not run this on the same server as a WordPress or other poorly designed frequently hacked web application.

Installation
------------

You can download this web application from github: <https://github.com/AliceWonderMiscreations/ColdAddress>

Unpack the zip archive:

    unzip ColdAddress-master.zip

This will result in a directory called `ColdAddress-master`

Move the archive to where you normally like to serve stuff from. Rename it to `ColdAddress` at the same time:

    mv ColdAddress-master /srv/ColdAddress

Assuming you are installing this on the same host as your browser, make an entry in your `/etc/hosts` file for the
domain `cold.address` pointing to `127.0.0.1` (or `::1`)

For example, if your existing `127.0.0.1` entry starts as:

    127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4

You would update it to look like

    127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4 cold.address

Create an Apache name-based virtual host. You may need to refer to the documentation specific to your install of Apache.

On Red Hat / Fedora systems, you can create a configuration file called `cold.address.conf` in the directory
`/etc/httpd/conf.d` containing the following:

    <VirtualHost 127.0.0.1:80>
    ServerName cold.address
    DocumentRoot "/srv/ColdAddress"
    ErrorLog logs/cold.address.error_log
    CustomLog logs/cold.address.access_log combined
    </VirtualHost>
    
    <Directory "/srv/ColdAddress">
      Options FollowSymlinks
      AllowOverride AuthConfig
      Require all granted
    </Directory>

Restart the Apache web server. Hopefully you can now access the web application at the url <http://cold.address> from
within your web browser. If not, the Apache `ErrorLog` defined above is your friend.

You will need to create a custom salt. The documentation on the web application page has details regarding how you can
do that.

Alice Wonder Miscreations

1KutggwB8VLGKTx7mgxrfiJusWCx2CWtFW
