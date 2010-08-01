<?php
require_once 'PHPUnit/Framework.php';
require_once 'lib/Pop3.php';
require_once 'tests/TestConfiguration.php';

use Mail\Protocol\Pop3;
use Mail\Protocol\Pop3_Exception;

class Pop3Test extends PHPUnit_Framework_TestCase
{
	protected $_connection;

	public function setUp()
	{
		$this->_connection = new Pop3(TESTS_MAIL_POP3_HOST, TESTS_MAIL_POP3_PORT, 'tls');
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

	public function testPop3TCPConnection()
	{
		$this->_connection = new Pop3(TESTS_MAIL_POP3_HOST, TESTS_MAIL_POP3_PORT, 'tcp');
		$this->assertFalse($this->_connection->isConnected());
		$this->_connection->connect();
		$this->assertTrue($this->_connection->isConnected());
		$this->_connection->close();
	}

	public function testPop3SSLConnection()
	{
		$this->_connection = new Pop3(TESTS_MAIL_POP3_HOST, TESTS_MAIL_POP3_SSL_PORT, 'ssl');
		$this->assertFalse($this->_connection->isConnected());
		$this->_connection->connect();
		$this->assertTrue($this->_connection->isConnected());
		$this->_connection->close();
	}

	public function testPop3TLSConnection()
	{
		$this->_connection = new Pop3(TESTS_MAIL_POP3_HOST, TESTS_MAIL_POP3_PORT, 'tls');
		$this->assertFalse($this->_connection->isConnected());
		$this->_connection->connect();
		$this->assertTrue($this->_connection->isConnected());
		$this->_connection->close();
	}

	public function testPop3AuthPlain()
	{
		$this->assertTrue($this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD, 'plain'));
	}

	public function testPop3AuthLogin()
	{
		$this->assertTrue($this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD, 'login'));
	}
	
	public function testPop3AuthPlainFail()
	{
		try {
			$this->_connection->authenticate('wrong', 'wrong', 'plain');
		}
		catch (Pop3_Exception $e) {
			return;
		}
		$this->fail();
	}

	public function testPop3AuthLoginFail()
	{
		try {
			$this->_connection->authenticate('wrong', 'wrong', 'login');
		}
		catch (Pop3_Exception $e) {
			return;
		}
		$this->fail();
	}

	public function testPop3CapaCommand()
	{
		$this->assertType('string', $this->_connection->getServerCapabilities('raw'));
		$this->assertType('array', $this->_connection->getServerCapabilities('array'));
		$this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD);
		$this->assertType('string', $this->_connection->getServerCapabilities('raw'));
		$this->assertType('array', $this->_connection->getServerCapabilities('array'));
	}

	public function testPop3StatCommand()
	{
		$this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD);
		$this->assertType('array', $this->_connection->status());
	}

	public function testPop3ListCommand()
	{
		$this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD);
		$this->assertType('array', $this->_connection->listMessages());
		$this->assertType('array', $this->_connection->listMessages(1));
	}

	public function testPop3RetrCommand()
	{
		$this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD);
		$this->assertType('string', $this->_connection->retrieve(1));
	}

	public function testPop3DeleCommand()
	{
		$this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD);
		$this->assertTrue($this->_connection->delete(1));
		$this->_connection->reset();
	}

	public function testPop3RsetCommand()
	{
		$this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD);
		$this->_connection->delete(1);
		$this->assertTrue($this->_connection->reset());
	}

	public function testPop3NoopCommand()
	{
		$this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD);
		$this->assertTrue($this->_connection->noop());
	}

	public function testPop3TopCommand()
	{
		$this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD);
		$this->assertType('string', $this->_connection->top(1));
	}

	public function testPop3UidlCommand()
	{
		$this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD);
		$this->assertType('array', $this->_connection->uidl());
		$this->assertType('array', $this->_connection->uidl(1));
	}

	public function testPop3QuitCommand()
	{
		$this->_connection->authenticate(TESTS_MAIL_POP3_USER, TESTS_MAIL_POP3_PASSWORD);
		$this->assertTrue($this->_connection->quit());
	}
}
?>
