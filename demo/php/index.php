<?php

date_default_timezone_set('UTC');

$policyJson = "{"
   ."\"Statement\": [{"
      ."\"Resource\":\"http://localhost:8099/private/success.jpg\","
      ."\"Condition\":{"
         ."\"DateLessThan\":{\"Apache:EpochTime\":" . (time()+(10*60)) . "},"
         ."\"DateGreaterThan\":{\"Apache:EpochTime\":" . (time()-(1*60)) . "},"
         ."\"IpAddress\":{\"Apache:SourceIp\":\"127.0.0.1\"}"
      ."}"
   ."}]"
."}";

$policyJson = str_replace(' ', '', $policyJson);
$base64PolicyJson = url_safe_base64_encode($policyJson);
$base64Signature = url_safe_base64_encode(rsa_sha1_sign($base64PolicyJson, "../samplekey.pem"));

echo "test page<br><br>";

echo '<a href="private/test.txt?policy=' . $base64PolicyJson . '&signature=' . $base64Signature . '">Text file</a><br><br>';

echo '<img src="private/success.jpg?policy=' . $base64PolicyJson . '&signature=' . $base64Signature . '">';

function rsa_sha1_sign($policy, $private_key_filename) {
   $signature = "";

   // load the private key
   $fp = fopen($private_key_filename, "r");
   $priv_key = fread($fp, 8192);
   fclose($fp);
   $pkeyid = openssl_get_privatekey($priv_key);

   // compute signature
   openssl_sign($policy, $signature, $pkeyid);

   // free the key from memory
   openssl_free_key($pkeyid);

   return $signature;
}

function url_safe_base64_encode($value) {
   $encoded = base64_encode($value);
   // replace unsafe characters +, = and / with
   // the safe characters -, _ and ~
   return str_replace(
       array('+', '=', '/'),
       array('-', '_', '~'),
       $encoded);
}