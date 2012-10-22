sqOpenID
========

"Smart mode" OpenID 2.0 Relay party

So far working with:
 * https://www.google.com/accounts/o8/id
 * me.yahoo.com
 * myopenid.com
 * sign.io

Based on LightOpenID but using smart mode "Association", fallback to stateless mode "dumb mode".

An association between the Relying Party and the OpenID Provider establishes a shared secret between them, which is used to verify subsequent protocol messages and reduce round trips.


Requirements:
============
PHP 5 or higher

PHP sessions (for verifying the nonce behind a load balancer)

PHP cURL Library

PHP GMP GNU Multiple Precision Library

PHP simpleXML (for yadis discovery)

PHP DOM Document Object Model (for parsing headers)

PHP HASH Message Digest Framework (for creating the signature)


Basic usage:
============

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

        /* email/name etc if available */
        $params = $oi->getAttributes();
      } else {
        return false;
      }
    } else {
      if ($oi->setIdentity('User-Supplied Identifier')->Discover()) {
        /* AX extension request fields */
        $oi->required('namePerson/friendly', 'contact/email', 'namePerson', 'birthDate', 'person/gender', 'contact/postalCode/home', 'contact/country/home');
        $oi->optional('pref/language', 'pref/timezone');

        /* redirect user to OP Endpoint URL */
        $oi->Auth();
      } else {
        echo 'no OP found';
      }
    }

work still pending...