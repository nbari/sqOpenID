<?php

require_once 'sqOpenid.php';

echo (new sqOpenID())->setIdentity('sign.io')->Discover() ? true : false;