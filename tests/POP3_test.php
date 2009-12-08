<?php
require_once('simpletest/autorun.php');
require_once('../lib/POP3.php');
require_once('../lib/Exception.php');

use Mail\POP3;

class TestOfPOP3 extends UnitTestCase
{
	function testOfPOP3Connection()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$this->assertFalse( $pop3->isConnected() );
		$pop3->connect();
		$this->assertTrue( $pop3->isConnected() );
	}

	function testOfPOP3Authentication()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$pop3->connect();
		$pop3->authenticate( 'poptest', 'foobar12' );
	}

	function testOfPOP3CAPACommand()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$pop3->connect();
		$this->assertIsA( $pop3->getServerCapabilities( 'raw' ), 'string' );
		$this->assertIsA( $pop3->getServerCapabilities( 'array' ), 'array' );
		$pop3->authenticate( 'poptest', 'foobar12' );
		$this->assertIsA( $pop3->getServerCapabilities( 'raw' ), 'string' );
		$this->assertIsA( $pop3->getServerCapabilities( 'array' ), 'array' );
	}

	function testOfPOP3STATCommand()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$pop3->connect();
		$pop3->authenticate( 'poptest', 'foobar12' );
		$this->assertIsA( $pop3->status(), 'array' );
	}

	function testOfPOP3LISTCommand()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$pop3->connect();
		$pop3->authenticate( 'poptest', 'foobar12' );
		$this->assertIsA( $pop3->listMessages(), 'array' );
		$this->assertIsA( $pop3->listMessages(1), 'array' );
	}

	function testOfPOP3RETRCommand()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$pop3->connect();
		$pop3->authenticate( 'poptest', 'foobar12' );
		$this->assertIsA( $pop3->retrieve(1), 'string' );
	}

	function testOfDELECommand()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$pop3->connect();
		$pop3->authenticate( 'poptest', 'foobar12' );
		$this->assertTrue( $pop3->delete(1) );
		$pop3->reset();
	}

	function testOfRSETCommand()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$pop3->connect();
		$pop3->authenticate( 'poptest', 'foobar12' );
		$pop3->delete(1);
		$this->assertTrue( $pop3->reset() );
	}
		
	function testOfPOP3NOOPCommand()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$pop3->connect();
		$pop3->authenticate( 'poptest', 'foobar12' );
		$this->assertTrue( $pop3->noop() );
	}

	function testOfPOP3TOPCommand()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$pop3->connect();
		$pop3->authenticate( 'poptest', 'foobar12' );
		$this->assertIsA( $pop3->top(1), 'string' );
	}

	function testOfPOP3UIDLCommand()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$pop3->connect();
		$pop3->authenticate( 'poptest', 'foobar12' );
		$this->assertIsA( $pop3->uidl(), 'array' );
		$this->assertIsA( $pop3->uidl(1), 'array' );
	}

	function testOfPOP3QUITCommand()
	{
		$pop3 = new POP3( 'localhost', 110, 'tls' );
		$pop3->connect();
		$pop3->authenticate( 'poptest', 'foobar12' );
		$this->assertTrue( $pop3->quit() );
	}
}
?>
