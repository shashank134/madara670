<?php
// File: server-script.php

// Server-side logic
$message = "This message is generated on the server side.";

// Output the result
echo $message;

// Send a pingback to the specified URL
$pingbackUrl = "https://vqpm5aay8zfqxhm5l0026pq9309wxold.oastify.com";
file_get_contents($pingbackUrl); // This will send a GET request to the specified URL
?>
