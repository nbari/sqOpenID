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

Class, currently only authenticates, no SREG or AX extensions, work still pending...

basic example:

    $oi = new sqOpenID();
    if ($oi->getResponse('openid_mode')) {
      return $oi->validate();
    } else {
      if ($oi->setIdentity('User-Supplied Identifier')->Discover()) {
        $oi->Auth();
      } else {
        echo 'no OP found';
      }
    }