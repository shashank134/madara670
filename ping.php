<?php
// File: server-script.php

// Server-side logic
$message = "This message is generated on the server side.";

// Output the result
echo $message;

// Send a pingback to the specified URL
$pingbackUrl = "https://vfex0gxn2ys7mfqvbfu0rxj3tuzmneh26.oastify.com";
file_get_contents($pingbackUrl); // This will send a GET request to the specified URL
?>
