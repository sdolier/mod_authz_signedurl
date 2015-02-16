<?php

$policyJson = "{"
   ."\"Statement\": [{"
      ."\"Resource\":\"http://localhost:8099/private/success.jpg\","
      ."\"Condition\":{"
         ."\"DateLessThan\":{\"Apache:EpochTime\":required ending date and time in Unix time format and UTC},"
         ."\"DateGreaterThan\":{\"Apache:EpochTime\":optional beginning date and time in Unix time format and UTC},"
         ."\"IpAddress\":{\"Apache:SourceIp\":\"optional IP address\"}"
      ."}"
   ."}]"
."}";

$policyJson = str_replace(' ', '', $policyJson);

echo "test page<br><br>";

echo '<a href="private/test.txt?policy=' . base64_encode($policyJson) . '&signiture=abc">Text file</a><br><br>';

echo '<img src="private/success.jpg?policy=' . base64_encode($policyJson) . '&signiture=abc">';