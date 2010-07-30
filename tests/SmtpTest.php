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

	public function setUp()
	{
		$this->_connection = new Smtp('localhost', 587, 'tls');
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
		$smtp = new Smtp('localhost', 25, 'tcp');
		$this->assertFalse($smtp->isConnected());
		$smtp->connect();
		$this->assertTrue($smtp->isConnected());
		$this->assertTrue($smtp->noop());
		$smtp->close();
	}

	public function testSmtpTLSConnection()
	{
		$smtp = new Smtp('localhost', 587, 'tls');
		$this->assertFalse($smtp->isConnected());
		$smtp->connect();
		$this->assertTrue($smtp->isConnected());
		$this->assertTrue($smtp->noop());
		$smtp->close();
	}

	public function testSmtpSSLConnection()
	{
		$smtp = new Smtp('localhost', 465, 'ssl');
		$this->assertFalse($smtp->isConnected());
		$smtp->connect();
		$this->assertTrue($smtp->isConnected());
		$this->assertTrue($smtp->noop());
		$smtp->close();
	}

	public function testSmtpHeloCommand()
	{
		$this->assertTrue($this->_connection->helo('localhost'));
	}

	public function testSmtpEhloCommand()
	{
		$this->assertType('array', $this->_connection->ehlo('localhost'));
	}

	public function testSmtpAuthPlain()
	{
		$this->_connection->helo('localhost');
		$this->assertTrue($this->_connection->authenticate('poptest', 'foobar12', 'plain'));
		/*
		$smtp->connect();
		$smtp->helo('localhost');
		try {
			$smtp->authenticate('wrong', 'wrong');
		}
		catch (Smtp_Exception $e) {
			return;
		}
		$smtp->close();
		$this->fail();
		*/
	}

	public function testSmtpAuthLogin()
	{
		$this->_connection->helo('localhost');
		$this->assertTrue($this->_connection->authenticate('poptest', 'foobar12', 'login'));
		/*
		$smtp->connect();
		$smtp->helo('localhost');
		try {
			$smtp->authenticate('wrong', 'wrong');
		}
		catch (Smtp_Exception $e) {
			return;
		}
		$smtp->close();
		$this->fail();
		*/
	}

	public function testSmtpMailCommand()
	{
		$this->_connection->helo('localhost');
		$this->_connection->authenticate('poptest', 'foobar12');
		$this->assertTrue($this->_connection->mail('poptest'));
	}

	public function testSmtpRcptCommand()
	{
		$this->_connection->helo('localhost');
		$this->_connection->authenticate('poptest', 'foobar12');
		$this->assertTrue($this->_connection->mail('poptest'));
		$this->assertTrue($this->_connection->rcpt('poptest'));
	}

	public function testSmtpDataCommand()
	{
		$mail = new Message();
		$mail->setFrom("poptest")
			 ->addTo("ryan")
			 ->setSubject("Test message from PHPUnit.")
			 ->setBody("Sent by SmtpTest::testSmtpDataCommand.");

		$this->_connection->helo('localhost');
		$this->_connection->authenticate('poptest', 'foobar12');
		$this->_connection->mail('poptest');
		$this->_connection->rcpt('ryan');
		$this->assertTrue($this->_connection->data($mail->toString()));
	}

	public function testSmtpRsetCommand()
	{
		$this->_connection->helo('localhost');
		$this->_connection->authenticate('poptest', 'foobar12');
		$this->_connection->mail('poptest');
		$this->_connection->rcpt('poptest');
		$this->assertTrue($this->_connection->reset());
	}

	public function testSmtpVrfyCommand()
	{
		$this->assertTrue($this->_connection->vrfy('poptest'));
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
		$this->_connection->authenticate('poptest', 'foobar12');
		$mail = new Message();
		$mail->setFrom('poptest', 'Sgt. Charles Zim')
			 ->addTo('ryan', 'Johnnie Rico')
			 ->addCc('poptest', 'Lt. Rasczak')
			 ->setPriority(Message::PRIORITY_HIGHEST)
			 ->setUserAgent('MailKit')
			 ->setSubject("Test message from PHPUnit.")
			 ->setBody("Sent by SmtpTest::testSmtpSend.");

		$this->_connection->send($mail);
	}
}
?>
