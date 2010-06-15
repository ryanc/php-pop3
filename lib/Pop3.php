<?php
require_once __DIR__ . '/Connection.php';
require_once __DIR__ . '/Pop3/Protocol.php';
require_once __DIR__ . '/Pop3/Exception.php';
require_once __DIR__ . '/Log.php';

$log = Log::singleton( './log/pop3.log' );
$log->open();
