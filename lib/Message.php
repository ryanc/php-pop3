<?php
/**
 * MailKit
 *
 * @package MailKit
 * @author Ryan Cavicchioni <ryan@confabulator.net>
 * @copyright Copyright (c) 2009-2010, Ryan Cavicchioni
 * @license http://www.opensource.org/licenses/bsd-license.php BSD Licnese
 * @todo Document the class.
 */

namespace Mail;

class Message
{
    public $to = array();
    public $cc = array();
    public $bcc = array();
    public $from = null;
    public $sender = null;
    public $reply_to = null;
    public $subject = null;
    public $body = null;
    public $headers = array();
    public $message_id = null;
    public $priority = null;
    public $user_agent = null;

    // Priorities for the X-Priority header.
    const PRIORITY_HIGHEST = 1;
    const PRIORITY_HIGH = 2;
    const PRIORITY_NORMAL = 3;
    const PRIORITY_LOW = 4;
    const PRIORITY_LOWEST = 5;

    const CRLF = "\r\n";

    public function add_to( $addr, $name = null )
    {
        $this->to[] = new Address( $addr, $name );
        return $this;
    }

    public function add_cc( $addr, $name = null )
    {
        $this->cc[] = new Address( $addr, $name );
        return $this;
    }

    public function add_bcc( $addr, $name = null )
    {
        $this->bcc[] = new Address( $addr, $name );
        return $this;
    }

    public function set_from( $addr, $name = null )
    {
        $this->from = new Address( $addr, $name );
        return $this;
    }

    public function set_sender( $addr, $name = null )
    {
        $this->sender = new Address( $addr, $name );
        return $this;
    }

    public function set_reply_to( $addr, $name = null )
    {
        $this->reply_to = new Address( $addr, $name );
        return $this;
    }

    public function set_subject( $subject )
    {
        $this->subject = trim( $subject );
        return $this;
    }

    public function set_body( $body )
    {
        $this->body = trim( $body );
        return $this;
    }

    public function set_priority( $priority = 3 )
    {
        $priority_map = array(
            1 => 'Highest',
            2 => 'High',
            3 => 'Normal',
            4 => 'Low',
            5 => 'Lowest'
        );

        $pmap_keys = array_keys( $priority_map );

        if ( $priority > 5 ) {
            $priority = max( $pmap_keys );
        }

        elseif ( $priority < 1 ) {
            $priority = min( $pmap_keys );
        }

        $this->priority = sprintf( "%d (%s)", $priority, $priority_map[$priority] );

        return $this;
    }

    public function set_user_agent( $user_agent )
    {
        $this->user_agent = $user_agent;
        return $this;
    }

    public function add_header( $name, $value )
    {
        $this->headers[$name] = $value;
    }

    private function _generate_message_id()
    {
        if ( extension_loaded( 'openssl' ) === true ) {
            $rand = openssl_random_pseudo_bytes(8);
        }

        else {
            $fp = fopen( '/dev/urandom', 'rb' );
            $rand = fread( $fp, 8 );
            fclose( $fp );
        }

        $hostname = gethostname();
        $this->message_id = '<' . sha1( $rand ) . '@' . $hostname . '>';
    }

    private function _build_headers()
    {
        if ( $this->from !== null ) {
            $this->add_header( "From", (string) $this->from );
        }
        if ( $this->sender !== null ) {
            $this->add_header( "Sender", (string) $this->sender );
        }
        if ( $this->reply_to !== null ) {
            $this->add_header( "Reply-To", (string) $this->reply_to );
        }
        if ( count( $this->to ) ) {
            $this->add_header( "To", implode( ", ", $this->to ) );
        }
        if ( count( $this->cc ) ) {
            $this->add_header( "Cc", implode( ", ", $this->cc ) );
        }
        if ( count( $this->bcc ) ) {
            $this->add_header( "Bcc" , implode( ", ", $this->cc ) );
        }
        if ( $this->priority !== null ) {
            $this->add_header( "X-Priority", $this->priority );
        }
        if ( $this->user_agent !== null ) {
            $this->add_header( "User-Agent", $this->user_agent );
        }

        $this->add_header( "Subject", $this->subject );
        $this->add_header( "Date", date("r") );

        $this->_generate_message_id();

        $this->add_header( "Message-ID", $this->message_id );
    }

    private function _generate_header()
    {
        $text = "";
        $this->_build_headers();

        foreach( $this->headers as $name => $value ) {
            $text .=  sprintf( "%s: %s%s",  $name, $value, self::CRLF );
        }

        return $text;
    }

    private function _generate_body()
    {
        return $this->body;
    }

    public function generate()
    {
        return $this->_generate_header() . self::CRLF . $this->_generate_body();
    }
}

/**
 * Message Exception class.
 *
 * @package MailKit
 * @author Ryan Cavicchioni <ryan@confabulator.net>
 * @copyright Copyright (c) 2009-2010, Ryan Cavicchioni
 * @license http://www.opensource.org/licenses/bsd-license.php BSD Licnese
 */
class Message_Exception extends \Exception {}

/**
 * Email address class.
 *
 * @package MailKit
 * @author Ryan Cavicchioni <ryan@confabulator.net>
 * @copyright Copyright (c) 2009-2010, Ryan Cavicchioni
 * @license http://www.opensource.org/licenses/bsd-license.php BSD Licnese
 */
class Address
{
    public $name = null;
    public $email = null;

    public function __construct( $email, $name = null )
    {
        $this->name = $name;
        $this->email = $email;
    }

    public function __toString()
    {
        if ( $this->name !== null && $this->email !== null ) {
            return sprintf( "\"%s\" <%s>", $this->name, $this->email );
        }

        else {
            return sprintf( "<%s>", $this->email );
        }
    }
}
?>
