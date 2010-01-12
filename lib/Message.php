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

	const CRLF = "\r\n";

	public function add_to( $addr )
	{
		$this->to[] = trim( $addr );
	}

	public function add_cc( $addr )
	{
		$this->cc[] = trim( $addr);
	}

	public function add_bcc( $addr )
	{
		$this->bcc[] = trim( $addr );
	}

	public function set_from( $addr )
	{
		$this->from = trim( $addr );
	}

	public function set_sender( $addr )
	{
		$this->sender = trim( $addr );
	}

	public function set_reply_to( $addr )
	{
		$this->reply_to = trim( $addr );
	}

	public function set_subject( $subject )
	{
		$this->subject = trim( $subject );
	}

	public function set_body( $body )
	{
		$this->body = trim( $body );
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
			$this->add_header( "From", $this->from );
		}
		if ( $this->sender !== null ) {
			$this->add_header( "Sender", $this->sender );
		}
		if ( $this->reply_to !== null ) {
			$this->add_header( "Reply-To", $this->reply_to );
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

		$this->add_header( "Subject", $this->subject );
		$this->add_header( "Date", date("r") );
		
		$this->_generate_message_id();

		$this->add_header( "Message-Id", $this->message_id );
	}

	private function _generate_header()
	{
		$text = "";
		$this->_build_headers();

		foreach( $this->headers as $name => $value ) {
			$text .= "{$name}: {$value}" . self::CRLF;
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
?>
