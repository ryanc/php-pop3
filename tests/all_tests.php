<?php
require_once( dirname(__FILE__) . '/simpletest/autorun.php' );
require_once( 'Pop3_test.php' );
require_once( 'Smtp_test.php' );

$test = &new GroupTest( 'All tests' );
$test->addTestCase( new TestOfPop3 );
$test->addTestCase( new TestOfSmtp );
$test->run( new HtmlReporter() );
?>
