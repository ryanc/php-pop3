<?php
require_once( dirname(__FILE__) . '/simpletest/autorun.php' );
require_once( 'Pop3_test.php' );

$test = &new GroupTest( 'All tests' );
$test->addTestCase( new TestOfPop3 );
$test->run( new HtmlReporter() );
?>
