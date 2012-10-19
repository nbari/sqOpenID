<?php

session_start();
require_once 'sqopenid.php';

?>
<!DOCTYPE html>
<html>
  <head>
    <meta charset='utf-8'>
    <title>OpenID RP</title>
    <style type="text/css">
      body {
       font-family:  'Helvetica Neue', Arial, 'Liberation Sans', FreeSans, sans-serif;
      }
      input {
        padding-right: 20px;
      }
      input#oi {
        padding-left: 20px;
        padding-right: 0px;
        background: transparent url('openid-16x16.gif') 3px 50% no-repeat;
      }
      #true { color: green}
      #false {color: red}
    </style>
  </head>
  <body>
    <h3>OpenID 2.0 Relying Party</h3>
    <form method="post">
      <input id="oi" type="text" name="openid_identifier" size="40" placeholder="enter your Identifier" />
      <input type="submit" value="Login test" />
    </form>
    <br>
    test-id.net identifiers to use:
<pre>
  * http://test-id.net/RP/HMACSHA256.aspx
  * http://test-id.net/RP/VerifyReturnTo.aspx
  * http://test-id.net/RP/VerifyAssertionDiscovery.aspx # needs to be checked, when  Claimed idnetifier as fragment or insignificant query fails
  * http://test-id.net/RP/SignatureCheck20.aspx
  * http://test-id.net/RP/ResponseNonceCheck.aspx
  * http://test-id.net/RP/DiscoveryAcceptHeader.aspx
  * http://test-id.net/RP/POSTAssertionWithUtf8.aspx
  * http://test-id.net/RP/SregAccountCreation.aspx?test=0Wi5vmzW

  others:
  * https://www.google.com/accounts/o8/id
  * me.yahoo.com
  * myopenid.com
  * user.sign.io #beta
</pre>
    <hr>
    <?php
      $oi = new sqOpenID();
      if ($oi->getResponse('openid_mode')) {
        echo 'response: <pre>';
        print_r($oi->getResponse());
        echo '</pre>Authentication: ' . ( $oi->validate() ? '<span id="true">True</span>' : '<span id="false">False</span>' );
        echo '<br>Claimed ID: ' . $oi->getClaimedID() .'<br>Attributes:<pre>';
        print_r($oi->getAttributes());
      } else {
        if (isset($_POST['openid_identifier'])) {
          if ($oi->setIdentity($_POST['openid_identifier'])->Discover()) {
            $oi->required('nickname', 'email', 'fullname', 'dob', 'gender', 'postcode', 'country');
            $oi->optional('language', 'timezone');
            /**
             * if OP Endpoint URL found, redirect the user to it.
             */
            $oi->Auth();
          }
        }
      }
    ?>
  </body>
</html>