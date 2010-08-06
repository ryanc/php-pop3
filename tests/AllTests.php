<?php

require_once 'PHPUnit/Framework.php';

require_once 'tests/SmtpTest.php';
require_once 'tests/Pop3Test.php';

require_once 'tests/TestConfiguration.php';

class Mailkit_AllTests
{
    public static function suite()
    {
        $suite = new PHPUnit_Framework_TestSuite('Mailkit Tests');
        if (TESTS_MAIL_SMTP_ENABLED === true) {
            $suite->addTestSuite('SmtpTest');
        } else {
            $suite->addTestSuite('SmtpTest_Skip');
        }

        if (TESTS_MAIL_POP3_ENABLED === true) {
            $suite->addTestSuite('Pop3Test');
        } else {
            $suite->addTestSuite('Pop3Test_Skip');
        }

        return $suite;
    }
}
