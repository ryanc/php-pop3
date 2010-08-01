<?php
require_once 'PHPUnit/Framework.php';
require_once 'lib/Smtp.php';
require_once 'lib/Message.php';
require_once 'tests/TestConfiguration.php';

use Mail\Message;
use Mail\Protocol\Smtp;
use Mail\Protocol\Smtp_Exception;

class SmtpTest extends PHPUnit_Framework_TestCase
{
	protected $_connection;

	public function setUp()
	{
		$this->_connection = new Smtp(TESTS_MAIL_SMTP_HOST, TESTS_MAIL_SMTP_SUBMISSION_PORT, 'tls');
		if ($this->_connection->isConnected() === false) {
			$this->_connection->connect();
		}
	}

	public function tearDown()
	{
		if ($this->_connection->isConnected() === true) {
			$this->_connection->close();
		}
	}

	public function testSmtpTCPConnection()
	{
		$smtp = new Smtp(TESTS_MAIL_SMTP_HOST, TESTS_MAIL_SMTP_PORT, 'tcp');
		$this->assertFalse($smtp->isConnected());
		$smtp->connect();
		$this->assertTrue($smtp->isConnected());
		$this->assertTrue($smtp->noop());
		$smtp->close();
	}

	public function testSmtpTLSConnection()
	{
		$smtp = new Smtp(TESTS_MAIL_SMTP_HOST, TESTS_MAIL_SMTP_SUBMISSION_PORT, 'tls');
		$this->assertFalse($smtp->isConnected());
		$smtp->connect();
		$this->assertTrue($smtp->isConnected());
		$this->assertTrue($smtp->noop());
		$smtp->close();
	}

	public function testSmtpSSLConnection()
	{
		$smtp = new Smtp(TESTS_MAIL_SMTP_HOST, TESTS_MAIL_SMTP_SSL_PORT, 'ssl');
		$this->assertFalse($smtp->isConnected());
		$smtp->connect();
		$this->assertTrue($smtp->isConnected());
		$this->assertTrue($smtp->noop());
		$smtp->close();
	}

	public function testSmtpHeloCommand()
	{
		$this->assertTrue($this->_connection->helo(TESTS_MAIL_SMTP_HOST));
	}

	public function testSmtpEhloCommand()
	{
		$this->assertType('array', $this->_connection->ehlo(TESTS_MAIL_SMTP_HOST));
	}

	public function testSmtpAuthPlain()
	{
		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->assertTrue($this->_connection->authenticate(TESTS_MAIL_SMTP_USER, TESTS_MAIL_SMTP_PASSWORD, 'plain'));
	}

	public function testSmtpAuthLogin()
	{
		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->assertTrue($this->_connection->authenticate(TESTS_MAIL_SMTP_USER, TESTS_MAIL_SMTP_PASSWORD, 'login'));
	}

	public function testSmtpAutoPlainFail()
	{
		$this->_connection->helo(TESTS_MAIL_SMTP_HOST); try {
			$this->_connection->authenticate('wrong', 'wrong', 'plain');
		}
		catch (Smtp_Exception $e) {
			return;
		}
		$this->fail();
	}

	public function testSmtpAuthLoginFail()
	{
		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		try {
			$this->_connection->authenticate('wrong', 'wrong', 'login');
		}
		catch (Smtp_Exception $e) {
			return;
		}
		$this->fail();
	}

	public function testSmtpMailCommand()
	{
		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->_connection->authenticate(TESTS_MAIL_SMTP_USER, TESTS_MAIL_SMTP_PASSWORD);
		$this->assertTrue($this->_connection->mail(TESTS_MAIL_SMTP_USER));
	}

	public function testSmtpRcptCommand()
	{
		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->_connection->authenticate(TESTS_MAIL_SMTP_USER, TESTS_MAIL_SMTP_PASSWORD);
		$this->assertTrue($this->_connection->mail(TESTS_MAIL_SMTP_USER));
		$this->assertTrue($this->_connection->rcpt(TESTS_MAIL_SMTP_USER));
	}

	public function testSmtpDataCommand()
	{
		$mail = new Message();
		$mail->setFrom("poptest")
			 ->addTo("ryan")
			 ->setSubject("Test message from PHPUnit.")
			 ->setBody("Sent by SmtpTest::testSmtpDataCommand.");

		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->_connection->authenticate(TESTS_MAIL_SMTP_USER, TESTS_MAIL_SMTP_PASSWORD);
		$this->_connection->mail(TESTS_MAIL_SMTP_USER);
		$this->_connection->rcpt('ryan');
		$this->assertTrue($this->_connection->data($mail->toString()));
	}

	public function testSmtpRsetCommand()
	{
		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->_connection->authenticate(TESTS_MAIL_SMTP_USER, TESTS_MAIL_SMTP_PASSWORD);
		$this->_connection->mail(TESTS_MAIL_SMTP_USER);
		$this->_connection->rcpt(TESTS_MAIL_SMTP_USER);
		$this->assertTrue($this->_connection->reset());
	}

	public function testSmtpVrfyCommand()
	{
		$this->assertTrue($this->_connection->vrfy(TESTS_MAIL_SMTP_USER));
		$this->assertFalse($this->_connection->vrfy('wrong'));
	}

	public function testSmtpQuitCommand()
	{
		$this->assertTrue($this->_connection->quit());
	}

	public function testSmtpNoopCommand()
	{
		$this->assertTrue($this->_connection->noop());
	}

	public function testSmtpSend()
	{
		$this->_connection->ehlo();
		$this->_connection->authenticate(TESTS_MAIL_SMTP_USER, TESTS_MAIL_SMTP_PASSWORD);
		$mail = new Message();
		$mail->setFrom(TESTS_MAIL_SMTP_USER, 'Sgt. Charles Zim')
			 ->addTo('ryan', 'Johnnie Rico')
			 ->addCc(TESTS_MAIL_SMTP_USER, 'Lt. Rasczak')
			 ->setPriority(Message::PRIORITY_HIGHEST)
			 ->setUserAgent('MailKit')
			 ->setSubject("Test message from PHPUnit.")
			 ->setBody("Sent by SmtpTest::testSmtpSend.");

		$this->_connection->send($mail);
	}
}
?>
