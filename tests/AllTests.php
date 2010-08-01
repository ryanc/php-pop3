<?php

require_once 'PHPUnit/Framework.php';

require_once 'tests/SmtpTest.php';
require_once 'tests/Pop3Test.php';

class Mailkit_AllTests
{
	public static function suite()
	{
		$suite = new PHPUnit_Framework_TestSuite('Mailkit Tests');

		$suite->addTestSuite('SmtpTest');
		$suite->addTestSuite('Pop3Test');

		return $suite;
	}
}
