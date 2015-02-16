<?php

echo "test page<br><br>";

echo '<img src="private/success.jpg?policy=' . base64_encode("this is a string that needs encoding") . '&signature=abc">';