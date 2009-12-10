<?php
require_once( dirname(__FILE__) . '/simpletest/autorun.php' );
require_once( 'POP3_test.php' );

$test = &new GroupTest( 'All tests' );
$test->addTestCase( new TestOfPOP3 );
$test->run( new HtmlReporter() );
?>
