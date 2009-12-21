<?php
require_once( dirname(__FILE__) . '/simpletest/autorun.php' );
require_once( '../lib/Smtp.php' );

use Mail\Protocol\Smtp;
use Mail\Protocol\SmtpException;

class TestOfSmtp extends UnitTestCase
{
	function testOfSmtpTCPConnection()
	{
		$smtp = new Smtp( 'localhost', 25, 'tcp' );
		$this->assertFalse( $smtp->isConnected() );
		$smtp->connect();
		$this->assertTrue( $smtp->isConnected() );
		$smtp->close();
	}

	function testOfHeloCommand()
	{
		$smtp = new Smtp( 'localhost', 25, 'tcp' );
		$smtp->connect();
		$this->assertTrue( $smtp->helo( 'localhost' ) );
		$smtp->close();
	}

	function testOfEhloCommand()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$this->assertIsA( $smtp->ehlo( 'localhost' ), 'array' );
		$smtp->close();
	}

	function testOfSmtpAuthPlain()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->helo( 'localhost' );
		$this->assertTrue( $smtp->authenticate( 'poptest', 'foobar12', 'PLAIN' ) );
		$smtp->close();

		$smtp->connect();
		$smtp->helo( 'localhost' );
		try {
			$smtp->authenticate( 'wrong', 'wrong' );
		} catch ( SmtpException $e ) {
			$this->pass();
		}
		$smtp->close();
	}

	function testOfSmtpAuthLogin()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->helo( 'localhost' );
		$this->assertTrue( $smtp->authenticate( 'poptest', 'foobar12', 'LOGIN' ) );
		$smtp->close();

		$smtp->connect();
		$smtp->helo( 'localhost' );
		try {
			$smtp->authenticate( 'wrong', 'wrong' );
		} catch ( SmtpException $e ) {
			$this->pass();
		}
		$smtp->close();
	}

	function testOfSmtpMailCommand()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->helo( 'localhost' );
		$smtp->authenticate( 'poptest', 'foobar12' );
		$this->assertTrue( $smtp->mail( 'poptest' ) );
		$smtp->close();
	}

	function testOfSmtpRcptCommand()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->helo( 'localhost' );
		$smtp->authenticate( 'poptest', 'foobar12' );
		$this->assertTrue( $smtp->mail( 'poptest' ) );
		$this->assertTrue( $smtp->rcpt( 'poptest' ) );
		$smtp->close();
	}

	function testOfSmtpDataCommand()
	{
		$data =  "From: Pop Test <poptest>\r\n";
		$data .= "To: Ryan Cavicchioni <ryan>\r\n";
		$data .= "Subject: Test\r\n";
		$data .= "\r\n";

		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$smtp->helo( 'localhost' );
		$smtp->authenticate( 'poptest', 'foobar12' );
		$smtp->mail( 'poptest' );
		$smtp->rcpt( 'ryan' );
		$this->assertTrue( $smtp->data( $data ) );
		$smtp->close();
	}

	function testOfSmtpRsetCommand()
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

	function testOfSmtpQuitCommand()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$this->assertTrue( $smtp->quit() );
		$smtp->close();
	}

	function testOfSmtpNoopCommand()
	{
		$smtp = new Smtp( 'localhost', 587, 'tls' );
		$smtp->connect();
		$this->assertTrue( $smtp->noop() );
		$smtp->close();
	}
}
?>
