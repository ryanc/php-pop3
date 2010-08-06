<?php
require_once 'PHPUnit/Framework.php';
require_once 'lib/Pop3.php';

use Mail\Protocol\Pop3,
    Mail\Protocol\Exception;

class Pop3Test extends PHPUnit_Framework_TestCase
{
    protected $_connection;

    protected $_authConfig = array(
      'user'      => TESTS_MAIL_POP3_USER,
      'password'  => TESTS_MAIL_POP3_PASSWORD,
      'mechanism' => 'plain'
    );

    public function setUp()
    {
        $config = array(
          'host'     => TESTS_MAIL_POP3_HOST,
          'port'     => TESTS_MAIL_POP3_PORT,
          'ssl_mode' => 'tls'
        );

        $this->_connection = new Pop3($config);
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
        $config = array(
          'host' => TESTS_MAIL_POP3_HOST,
          'port' => TESTS_MAIL_POP3_PORT,
        );

        $this->_connection = new Pop3($config);
        $this->assertFalse(
          $this->_connection->isConnected()
        );
        $this->_connection->connect();
        $this->assertTrue(
          $this->_connection->isConnected()
        );
        $this->_connection->close();
    }

    public function testPop3SSLConnection()
    {
        $config = array(
          'host'     => TESTS_MAIL_POP3_HOST,
          'port'     => TESTS_MAIL_POP3_SSL_PORT,
          'ssl_mode' => 'ssl'
        );

        $this->_connection = new Pop3($config);
        $this->assertFalse(
          $this->_connection->isConnected()
        );
        $this->_connection->connect();
        $this->assertTrue(
          $this->_connection->isConnected()
        );
        $this->_connection->close();
    }

    public function testPop3TLSConnection()
    {
        $config = array(
          'host'     => TESTS_MAIL_POP3_HOST,
          'port'     => TESTS_MAIL_POP3_PORT,
          'ssl_mode' => 'tls'
        );

        $this->_connection = new Pop3($config);
        $this->assertFalse(
          $this->_connection->isConnected()
        );
        $this->_connection->connect();
        $this->assertTrue(
          $this->_connection->isConnected()
        );
        $this->_connection->close();
    }

    public function testConnectionFailure()
    {
        $config = array(
          'host'    => 'host.example.invalid',
        );

        $this->_connection = new Pop3($config);
        try {
            $this->_connection->connect();
        }

        catch (Mail\Protocol\Exception $e) {
            return;
        }

        $this->fail('No exception was raised while connecting to an invalid host.');
    }

    public function testConnectionToInvalidPort()
    {
        $config = array(
          'host'    => TESTS_MAIL_POP3_HOST,
          'port'    => TESTS_MAIL_POP3_INVALID_PORT,
        );

        $this->_connection = new Pop3($config);
        try {
            $this->_connection->connect();
        }

        catch (Mail\Protocol\Exception $e) {
            return;
        }

        $this->fail('No exception was raised while connecting to an invalid port.');
    }

    public function testConnectionToWrongPort()
    {
        $config = array(
          'host'    => TESTS_MAIL_POP3_HOST,
          'port'    => TESTS_MAIL_POP3_WRONG_PORT,
        );

        $this->_connection = new Pop3($config);
        try {
            $this->_connection->connect();
        }

        catch (Mail\Protocol\Exception $e) {
            return;
        }

        $this->fail('No exception was raised while connecting to the wrong port.');
    }

    public function testPop3AuthPlain()
    {
        $this->assertTrue(
          $this->_connection->authenticate($this->_authConfig)
        );
    }

    public function testPop3AuthLogin()
    {
        $authConfig = array(
          'user'      => TESTS_MAIL_POP3_USER,
          'password'  => TESTS_MAIL_POP3_PASSWORD,
          'mechanism' => 'login'
        );

        $this->assertTrue(
          $this->_connection->authenticate($authConfig)
        );
    }

    public function testPop3AuthPlainFail()
    {
        $authConfig = array(
          'user'      => 'wrong',
          'password'  => 'wrong',
          'mechanism' => 'plain'
        );

        try {
            $this->_connection->authenticate($authConfig);
        }
        catch (Mail\Protocol\Exception $e) {
            return;
        }
        $this->fail();
    }

    public function testPop3AuthLoginFail()
    {
        $authConfig = array(
          'user'      => 'wrong',
          'password'  => 'wrong',
          'mechanism' => 'login'
        );

        try {
            $this->_connection->authenticate($authConfig);
        }
        catch (Mail\Protocol\Exception $e) {
            return;
        }
        $this->fail();
    }

    public function testPop3CapaCommand()
    {
        $this->assertType(
          'string',
          $this->_connection->getServerCapabilities('raw')
        );
        $this->assertType(
          'array',
          $this->_connection->getServerCapabilities('array')
        );
        $this->_connection->authenticate($this->_authConfig);
        $this->assertType(
          'string',
          $this->_connection->getServerCapabilities('raw')
        );
        $this->assertType(
          'array',
          $this->_connection->getServerCapabilities('array')
        );
    }

    public function testPop3StatCommand()
    {
        $this->_connection->authenticate($this->_authConfig);
        $this->assertType(
          'array',
          $this->_connection->status()
        );
    }

    public function testPop3ListCommand()
    {
        $this->_connection->authenticate($this->_authConfig);
        $this->assertType(
          'array',
          $this->_connection->listMessages()
        );
        $this->assertType(
          'array',
          $this->_connection->listMessages(1)
        );
    }

    public function testPop3RetrCommand()
    {
        $this->_connection->authenticate($this->_authConfig);
        $this->assertType(
          'string',
          $this->_connection->retrieve(1)
        );
    }

    public function testPop3DeleCommand()
    {
        $this->_connection->authenticate($this->_authConfig);
        $this->assertTrue(
          $this->_connection->delete(1)
        );
        $this->_connection->reset();
    }

    public function testPop3RsetCommand()
    {
        $this->_connection->authenticate($this->_authConfig);
        $this->_connection->delete(1);
        $this->assertTrue(
          $this->_connection->reset()
        );
    }

    public function testPop3NoopCommand()
    {
        $this->_connection->authenticate($this->_authConfig);
        $this->assertTrue(
          $this->_connection->noop()
        );
    }

    public function testPop3TopCommand()
    {
        $this->_connection->authenticate($this->_authConfig);
        $this->assertType(
          'string',
          $this->_connection->top(1)
        );
    }

    public function testPop3UidlCommand()
    {
        $this->_connection->authenticate($this->_authConfig);
        $this->assertType(
          'array',
          $this->_connection->uidl()
        );
        $this->assertType(
          'array',
          $this->_connection->uidl(1)
        );
    }

    public function testPop3QuitCommand()
    {
        $this->_connection->authenticate($this->_authConfig);
        $this->assertTrue(
          $this->_connection->quit()
        );
    }
}

class Pop3Test_Skip extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->markTestSkipped('POP3 tests are not enabled.');
    }

    public function testDoNothing() {}
}

?>
