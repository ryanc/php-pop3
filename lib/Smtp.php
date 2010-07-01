<?php
require_once __DIR__ . '/Connection.php';
require_once __DIR__ . '/Smtp/Protocol.php';
require_once __DIR__ . '/Smtp/Exception.php';
require_once __DIR__ . '/Log.php';

$log = Log::singleton('./log/pop3.log');
$log->open();
