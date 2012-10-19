sqOpenID - BETA
===============

"Smart mode" OpenID 2.0 Relay party

Based on LightOpenID but using smart mode "Association"

An association between the Relying Party and the OpenID Provider establishes a shared secret between them, which is used to verify subsequent protocol messages and reduce round trips.

Requirements:
============
PHP 5 or higher

PHP cURL Library

PHP GMP GNU Multiple Precision Library

PHP simpleXML (for yadis discovery)

PHP DOM Document Object Model (for parsing headers)

PHP HASH Message Digest Framework (for creating the signature)


Basic usage:
===========

In cases where you want to add users to a system via 'webform' and want to verify if the OP Endpoing exists, you can use something like:

<code>
echo (new sqOpenID())->setIdentity('User-Supplied Identifier')->Discover() ? true : false;
</code>

For a full authentication flow, check the form in file 'index.php'.

Basic example:

    $oi = new sqOpenID();
    if ($oi->getResponse('openid_mode')) {
      if ($oi->validate()) {
        /* id to store on DB etc.*/
        $claimed_id = $oi->getClaimedID();
      } else {
        return false;
      }
    } else {
      if ($oi->setIdentity('User-Supplied Identifier')->Discover()) {
        /* sred/ax request fields */
        $oi->required('nickname', 'email', 'fullname', 'dob', 'gender', 'postcode', 'country');
        $oi->optional('language', 'timezone');

        /* redirect user to OP Endpoint URL */
        $oi->Auth();
      } else {
        echo 'no OP found';
      }
    }