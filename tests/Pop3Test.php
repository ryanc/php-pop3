<?php
require_once 'PHPUnit/Framework.php';
require_once 'lib/Pop3.php';

use Mail\Protocol\Pop3;
use Mail\Protocol\Pop3_Exception;

class Pop3Test extends PHPUnit_Framework_TestCase
{
    public function testPop3TCPConnection()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tcp' );
        $this->assertFalse( $pop3->is_connected() );
        $pop3->connect();
        $this->assertTrue( $pop3->is_connected() );
        $pop3->close();
    }

    public function testPop3SSLConnection()
    {
        $pop3 = new Pop3( 'localhost', 995, 'ssl' );
        $this->assertFalse( $pop3->is_connected() );
        $pop3->connect();
        $this->assertTrue( $pop3->is_connected() );
        $pop3->close();
    }

    public function testPop3TLSConnection()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $this->assertFalse( $pop3->is_connected() );
        $pop3->connect();
        $this->assertTrue( $pop3->is_connected() );
        $pop3->close();
    }

    public function testPop3AuthPlain()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $this->assertTrue( $pop3->authenticate( 'poptest', 'foobar12', 'plain' ) );
        $pop3->close();
        $pop3->connect();
        try {
            $pop3->authenticate( 'wrong', 'wrong' );
        }
        catch ( Pop3_Exception $e ) {
            return;
        }
        $pop3->close();
        $this->fail();
    }

    public function testPop3AuthLogin()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $this->assertTrue( $pop3->authenticate( 'poptest', 'foobar12', 'login' ) );
        $pop3->close();
        $pop3->connect();
        try {
            $pop3->authenticate( 'wrong', 'wrong' );
        }
        catch ( Pop3_Exception $e ) {
            return;
        }
        $pop3->close();
        $this->fail();
    }

    public function testPop3CapaCommand()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $this->assertType( 'string', $pop3->get_server_capabilities( 'raw' ) );
        $this->assertType( 'array', $pop3->get_server_capabilities( 'array' ) );
        $pop3->authenticate( 'poptest', 'foobar12' );
        $this->assertType( 'string', $pop3->get_server_capabilities( 'raw' ) );
        $this->assertType( 'array', $pop3->get_server_capabilities( 'array' ) );
        $pop3->close();
    }

    public function testPop3StatCommand()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $pop3->authenticate( 'poptest', 'foobar12' );
        $this->assertType( 'array', $pop3->status() );
        $pop3->close();
    }

    public function testPop3ListCommand()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $pop3->authenticate( 'poptest', 'foobar12' );
        $this->assertType( 'array', $pop3->list_messages() );
        $this->assertType( 'array', $pop3->list_messages(1) );
        $pop3->close();
    }

    public function testPop3RetrCommand()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $pop3->authenticate( 'poptest', 'foobar12' );
        $this->assertType( 'string', $pop3->retrieve(1) );
        $pop3->close();
    }

    public function testPop3DeleCommand()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $pop3->authenticate( 'poptest', 'foobar12' );
        $this->assertTrue( $pop3->delete(1) );
        $pop3->reset();
        $pop3->close();
    }

    public function testPop3RsetCommand()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $pop3->authenticate( 'poptest', 'foobar12' );
        $pop3->delete(1);
        $this->assertTrue( $pop3->reset() );
        $pop3->close();
    }

    public function testPop3NoopCommand()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $pop3->authenticate( 'poptest', 'foobar12' );
        $this->assertTrue( $pop3->noop() );
        $pop3->close();
    }

    public function testPop3TopCommand()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $pop3->authenticate( 'poptest', 'foobar12' );
        $this->assertType( 'string', $pop3->top(1) );
        $pop3->close();
    }

    public function testPop3UidlCommand()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $pop3->authenticate( 'poptest', 'foobar12' );
        $this->assertType( 'array', $pop3->uidl() );
        $this->assertType( 'array', $pop3->uidl(1) );
        $pop3->close();
    }

    public function testPop3QuitCommand()
    {
        $pop3 = new Pop3( 'localhost', 110, 'tls' );
        $pop3->connect();
        $pop3->authenticate( 'poptest', 'foobar12' );
        $this->assertTrue( $pop3->quit() );
        $pop3->close();
    }
}
?>
