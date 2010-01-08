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

	public function addTo( $addr )
	{
		$this->to[] = trim( $addr );
	}

	public function addCc( $addr )
	{
		$this->cc[] = trim( $addr);
	}

	public function addBcc( $addr )
	{
		$this->bcc[] = trim( $addr );
	}

	public function setFrom( $addr )
	{
		$this->from = trim( $addr );
	}

	public function setSender( $addr )
	{
		$this->sender = trim( $addr );
	}

	public function setReplyTo( $addr )
	{
		$this->reply_to = trim( $addr );
	}

	public function setSubject( $subject )
	{
		$this->subject = trim( $subject );
	}

	public function setBody( $body )
	{
		$this->body = trim( $body );
	}

	public function addHeader( $name, $value )
	{
		$this->headers[$name] = $value;
	}

	private function _generateMessageId()
	{
		$rand = openssl_random_pseudo_bytes(8);
		$hostname = gethostname();
		$this->message_id = '<' . sha1( $rand ) . '@' . $hostname . '>';
	}

	private function _buildHeaders()
	{
		if ( $this->from !== null ) {
			$this->addHeader( "From", $this->from );
		}
		if ( $this->sender !== null ) {
			$this->addHeader( "Sender", $this->sender );
		}
		if ( $this->reply_to !== null ) {
			$this->addHeader( "Reply-To", $this->reply_to );
		}
		if ( count( $this->to ) ) {
			$this->addHeader( "To", implode( ", ", $this->to ) );
		}
		if ( count( $this->cc ) ) {
			$this->addHeader( "Cc", implode( ", ", $this->cc ) );
		}
		if ( count( $this->bcc ) ) {
			$this->addHeader( "Bcc" , implode( ", ", $this->cc ) );
		}

		$this->addHeader( "Subject", $this->subject );
		$this->addHeader( "Date", date("r") );
		
		$this->_generateMessageId();

		$this->addHeader( "Message-Id", $this->message_id );
	}

	private function _generateHeader()
	{
		$text = "";
		$this->_buildHeaders();

		foreach( $this->headers as $name => $value ) {
			$text .= "{$name}: {$value}" . self::CRLF;
		}

		return $text;
	}

	private function _generateBody()
	{
		return $this->body;
	}

	public function generate()
	{
		return $this->_generateHeader() . self::CRLF . $this->_generateBody();
	}
}
?>
