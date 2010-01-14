<?php
require_once 'PHPUnit/Framework.php';
require_once 'lib/Smtp.php';
require_once 'lib/Message.php';

use Mail\Message;
use Mail\Protocol\Smtp;
use Mail\Protocol\Smtp_Exception;

class SmtpTest extends PHPUnit_Framework_TestCase
{
	public function testSmtpTCPConnection()
	{
		$smtp = new Smtp( 'localhost', 25, 'tcp' );
		$this->assertFalse( $smtp->is_connected() );
		$smtp->connect();
		$this->assertTrue( $smtp->is_connected() );
		$this->assertTrue( $smtp->noop() );
		$smtp->close();
	}

	public function testSmtpTLSConnection()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$this->assertFalse( $smtp->is_connected() );
		$smtp->connect();
		$this->assertTrue( $smtp->is_connected() );
		$this->assertTrue( $smtp->noop() );
		$smtp->close();
	}

	public function testSmtpSSLConnection()
	{
		$smtp = new Smtp( 'localhost', 465, 'ssl' );
		$this->assertFalse( $smtp->is_connected() );
		$smtp->connect();
		$this->assertTrue( $smtp->is_connected() );
		$this->assertTrue( $smtp->noop() );
		$smtp->close();
	}

	public function testSmtpHeloCommand()
	{
		$smtp = new Smtp( 'localhost', 25, 'tcp' );
		$smtp->connect();
		$this->assertTrue( $smtp->helo( 'localhost' ) );
		$smtp->close();
	}

	public function testSmtpEhloCommand()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$this->assertType( 'array', $smtp->ehlo( 'localhost' ) );
		$smtp->close();
	}

	public function testSmtpAuthPlain()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->helo( 'localhost' );
		$this->assertTrue( $smtp->authenticate( 'poptest', 'foobar12', 'plain' ) );
		$smtp->close();

		$smtp->connect();
		$smtp->helo( 'localhost' );
		try {
			$smtp->authenticate( 'wrong', 'wrong' );
		}
		catch ( Smtp_Exception $e ) {
			return;
		}
		$smtp->close();
		$this->fail();
	}

	public function testSmtpAuthLogin()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->helo( 'localhost' );
		$this->assertTrue( $smtp->authenticate( 'poptest', 'foobar12', 'login' ) );
		$smtp->close();

		$smtp->connect();
		$smtp->helo( 'localhost' );
		try {
			$smtp->authenticate( 'wrong', 'wrong' );
		}
		catch ( Smtp_Exception $e ) {
			return;
		}
		$smtp->close();
		$this->fail();
	}

	public function testSmtpMailCommand()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->helo( 'localhost' );
		$smtp->authenticate( 'poptest', 'foobar12' );
		$this->assertTrue( $smtp->mail( 'poptest' ) );
		$smtp->close();
	}

	public function testSmtpRcptCommand()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->helo( 'localhost' );
		$smtp->authenticate( 'poptest', 'foobar12' );
		$this->assertTrue( $smtp->mail( 'poptest' ) );
		$this->assertTrue( $smtp->rcpt( 'poptest' ) );
		$smtp->close();
	}

	public function testSmtpDataCommand()
	{
		$mail = new Message();
		$mail->set_from("poptest");
		$mail->add_to("ryan");
		$mail->set_subject( "Test message from PHPUnit." );
		$mail->set_body( "Sent by SmtpTest::testSmtpDataCommand." );

		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->helo( 'localhost' );
		$smtp->authenticate( 'poptest', 'foobar12' );
		$smtp->mail( 'poptest' );
		$smtp->rcpt( 'ryan' );
		$this->assertTrue( $smtp->data( $mail->generate() ) );
		$smtp->close();
	}

	public function testSmtpRsetCommand()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->helo( 'localhost' );
		$smtp->authenticate( 'poptest', 'foobar12' );
		$smtp->mail( 'poptest' );
		$smtp->rcpt( 'poptest' );
		$this->assertTrue( $smtp->reset() );
		$smtp->close();
	}

	public function testSmtpVrfyCommand()
	{
		$smtp = new Smtp( 'localhost', 25, 'tcp' );
		$smtp->connect();
		$this->assertTrue( $smtp->vrfy( 'poptest' ) );
		$this->assertFalse( $smtp->vrfy( 'wrong' ) );
		$smtp->close();
	}

	public function testSmtpQuitCommand()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$this->assertTrue( $smtp->quit() );
		$smtp->close();
	}

	public function testSmtpNoopCommand()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$this->assertTrue( $smtp->noop() );
		$smtp->close();
	}

	public function testSmtpSend()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->ehlo();
		$smtp->authenticate( 'poptest', 'foobar12' );
		$mail = new Message();
		$mail->set_from( 'poptest', 'Sgt. Charles Zim' );
		$mail->add_to( 'ryan', 'Johnnie Rico' );
		$mail->add_cc( 'poptest', 'Lt. Rasczak' );
		$mail->set_priority( Message::PRIORITY_HIGHEST );
		$mail->set_subject( "Test message from PHPUnit." );
		$mail->set_body( "Sent by SmtpTest::testSmtpSend." );

		$smtp->send( $mail );
	}
}
?>
