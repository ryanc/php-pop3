<?php
require_once 'PHPUnit/Framework.php';
require_once 'lib/Smtp.php';
require_once 'lib/Message.php';

use Mail\Message;
use Mail\Protocol\Smtp;
use Mail\Protocol\Smtp_Exception;

class SmtpTest extends PHPUnit_Framework_TestCase
{
	protected $_connection;

	protected $_authConfig = array(
	  'user'      => TESTS_MAIL_SMTP_USER,
	  'password'  => TESTS_MAIL_SMTP_PASSWORD,
	  'mechanism' => 'plain'
	);

	public function setUp()
	{
		$config = array(
		  'host'	 => TESTS_MAIL_SMTP_HOST,
		  'port'	 => TESTS_MAIL_SMTP_SUBMISSION_PORT,
		  'ssl_mode' => 'tls'
		);

		$this->_connection = new Smtp($config);
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
		$config = array(
		  'host' => TESTS_MAIL_SMTP_HOST,
		  'port' => TESTS_MAIL_SMTP_PORT,
		);

		$this->_connection = new Smtp($config);
		$this->assertFalse(
		  $this->_connection->isConnected()
		);
		$this->_connection->connect();
		$this->assertTrue(
		  $this->_connection->isConnected()
		);
		$this->assertTrue(
		  $this->_connection->noop()
		);
		$this->_connection->close();
	}

	public function testSmtpTLSConnection()
	{
		$config = array(
		  'host'	 => TESTS_MAIL_SMTP_HOST,
		  'port'	 => TESTS_MAIL_SMTP_SUBMISSION_PORT,
		  'ssl_mode' => 'tls'
		);

		$this->_connection = new Smtp($config);
		$this->assertFalse(
		  $this->_connection->isConnected()
		);
		$this->_connection->connect();
		$this->assertTrue(
		  $this->_connection->isConnected()
		);
		$this->assertTrue(
		  $this->_connection->noop()
		);
		$this->_connection->close();
	}

	public function testSmtpSSLConnection()
	{
		$config = array(
		  'host'	 => TESTS_MAIL_SMTP_HOST,
		  'port'	 => TESTS_MAIL_SMTP_SSL_PORT,
		  'ssl_mode' => 'ssl'
		);

		$this->_connection = new Smtp($config);
		$this->assertFalse(
		  $this->_connection->isConnected()
		);
		$this->_connection->connect();
		$this->assertTrue(
		  $this->_connection->isConnected()
		);
		$this->assertTrue(
		  $this->_connection->noop()
		);
		$this->_connection->close();
	}

	public function testSmtpHeloCommand()
	{
		$this->assertTrue(
		  $this->_connection->helo(TESTS_MAIL_SMTP_HOST)
		);
	}

	public function testSmtpEhloCommand()
	{
		$this->assertType(
		  'array', $this->_connection->ehlo(TESTS_MAIL_SMTP_HOST)
		);
	}

	public function testSmtpAuthPlain()
	{
		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->assertTrue(
		  $this->_connection->authenticate($this->_authConfig)
		);
	}

	public function testSmtpAuthLogin()
	{
		$authConfig = array(
		  'user'      => TESTS_MAIL_SMTP_USER,
		  'password'  => TESTS_MAIL_SMTP_PASSWORD,
		  'mechanism' => 'login'
		);

		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->assertTrue(
		  $this->_connection->authenticate($authConfig)
		);
	}

	public function testSmtpAuthPlainFail()
	{
		$authConfig = array(
		  'user'      => 'wrong',
		  'password'  => 'wrong',
		  'mechanism' => 'plain'
		);

		$this->_connection->helo(TESTS_MAIL_SMTP_HOST); try {
			$this->_connection->authenticate($authConfig);
		}
		catch (Smtp_Exception $e) {
			return;
		}
		$this->fail();
	}

	public function testSmtpAuthLoginFail()
	{
		$authConfig = array(
		  'user'      => 'wrong',
		  'password'  => 'wrong',
		  'mechanism' => 'login'
		);

		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		try {
			$this->_connection->authenticate($authConfig);
		}
		catch (Smtp_Exception $e) {
			return;
		}
		$this->fail();
	}

	public function testSmtpMailCommand()
	{
		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->_connection->authenticate($this->_authConfig);
		$this->assertTrue(
		  $this->_connection->mail(TESTS_MAIL_SMTP_USER)
		);
	}

	public function testSmtpRcptCommand()
	{
		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->_connection->authenticate($this->_authConfig);
		$this->assertTrue(
		  $this->_connection->mail(TESTS_MAIL_SMTP_USER)
		);
		$this->assertTrue(
		  $this->_connection->rcpt(TESTS_MAIL_SMTP_USER)
		);
	}

	public function testSmtpDataCommand()
	{
		$mail = new Message();
		$mail->setFrom("poptest")
			 ->addTo("ryan")
			 ->setSubject("Test message from PHPUnit.")
			 ->setBody("Sent by SmtpTest::testSmtpDataCommand.");

		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->_connection->authenticate($this->_authConfig);
		$this->_connection->mail(TESTS_MAIL_SMTP_USER);
		$this->_connection->rcpt('ryan');
		$this->assertTrue(
		  $this->_connection->data($mail->toString())
		);
	}

	public function testSmtpRsetCommand()
	{
		$this->_connection->helo(TESTS_MAIL_SMTP_HOST);
		$this->_connection->authenticate($this->_authConfig);
		$this->_connection->mail(TESTS_MAIL_SMTP_USER);
		$this->_connection->rcpt(TESTS_MAIL_SMTP_USER);
		$this->assertTrue(
		  $this->_connection->reset()
		);
	}

	public function testSmtpVrfyCommand()
	{
		$this->assertTrue(
		  $this->_connection->vrfy(TESTS_MAIL_SMTP_USER)
		);
		$this->assertFalse(
		  $this->_connection->vrfy('wrong')
		);
	}

	public function testSmtpQuitCommand()
	{
		$this->assertTrue(
		  $this->_connection->quit()
		);
	}

	public function testSmtpNoopCommand()
	{
		$this->assertTrue(
		  $this->_connection->noop()
		);
	}

	public function testSmtpSend()
	{
		$this->_connection->ehlo();
		$this->_connection->authenticate($this->_authConfig);
		$mail = new Message();
		$mail->setFrom(TESTS_MAIL_SMTP_USER, 'Sgt. Charles Zim')
			 ->addTo('ryan', 'Johnnie Rico')
			 ->addCc(TESTS_MAIL_SMTP_USER, 'Lt. Rasczak')
			 ->setPriority(Message::PRIORITY_HIGHEST)
			 ->setUserAgent('MailKit')
			 ->setSubject("Test message from PHPUnit.")
			 ->setBody("Sent by SmtpTest::testSmtpSend.");

		$this->assertTrue(
		  $this->_connection->send($mail)
		);
	}
}

class SmtpTest_Skip extends PHPUnit_Framework_TestCase
{
	public function setUp()
	{
		$this->markTestSkipped('SMTP tests are not enabled.');
	}

	public function testDoNothing()
	{
	}
}
?>
