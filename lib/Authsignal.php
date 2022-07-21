<?php

if (!function_exists('curl_init')) {
  throw new Exception('Authsignal needs the CURL PHP extension.');
}
if (!function_exists('json_decode')) {
  throw new Exception('Authsignal needs the JSON PHP extension.');
}

if (!function_exists('lcfirst'))
{
  function lcfirst( $str ) {
    $str[0] = strtolower($str[0]);
    return (string)$str;
  }
}

require(dirname(__FILE__) . '/Authsignal/Authsignal.php');
require(dirname(__FILE__) . '/Authsignal/AuthsignalClient.php');
require(dirname(__FILE__) . '/Authsignal/AuthsignalRequestTransport.php');
require(dirname(__FILE__) . '/Authsignal/Errors.php');