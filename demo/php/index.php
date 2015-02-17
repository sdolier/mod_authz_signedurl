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

echo "test page<br><br>";

echo '<a href="private/test.txt?policy=' . base64_encode($policyJson) . '&signiture=abc">Text file</a><br><br>';

echo '<img src="private/success.jpg?policy=' . base64_encode($policyJson) . '&signiture=abc">';