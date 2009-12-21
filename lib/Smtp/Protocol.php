<?php

namespace Mail\Protocol;
use Mail\Connection;

class Smtp extends Connection
{
	const STATE_NOT_CONNECTED = 0;
	const STATE_CONNECTED = 1;
	const STATE_AUTHENTICATED = 2;

	public function connect()
	{
		parent::connect();

		if ( $this->transport === 'tls' )
			$this->starttls();
	}

	protected function starttls()
	{
		$this->send( "STARTTLS" );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 220 ) === false )
			throw new SmtpException( "The server returned a negative response to the STARTTLS command: {$resp}" );

		parent::starttls();

		return true;
	}

	public function authenticate( $username, $password )
	{
		// Validate session state.
		$auth_string = base64_encode( "\0{$username}\0{$password}" );

		$this->send( "AUTH PLAIN {$auth_string}" );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 235 ) === false )
			throw new SmtpException( "Authentication failed: ${resp}" );
	}

	protected function isGreetingOK( $resp )
	{
		if ( strpos( $resp, "220" ) === 0 )
			return true;

		return false;
	}

	protected function isResponseOK( $resp, $expect )
	{
		if ( strpos( $resp, (string) $expect ) === 0 )
			return true;

		return false;
	}

	public function helo( $hostname = 'localhost' )
	{
		$this->send( "HELO {$hostname}" );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the HELO command: {$resp}" );

		return true;
	}

	public function ehlo( $hostname = 'localhost' )
	{
		$buf = array();
		$this->send( "EHLO {$hostname}" );

		do {
			$resp = $this->getResponse( true );

			if ( $this->isResponseOK( $resp, 250 ) === false )
				throw new SmtpException( "The server returned a negative response to the EHLO command: {$resp}" );

			$buf[] = ltrim( $resp, "250- " );
		} while ( strpos( $resp, '-' ) === 3 );

		return $buf;
	}

	public function mail ( $from )
	{
		$this->send( "MAIL FROM: <{$from}>" );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the MAIL command: {$resp}" );

		return true;
	}

	public function rcpt ( $to )
	{
		$this->send( "RCPT TO: <{$to}>" );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the RCPT command: {$resp}" );

		return true;
	}

	public function data ( $data )
	{
		$this->send( "DATA" );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 354 ) === false )
			throw new SmtpException( "The server returned a negative response to the DATA command: {$resp}" );

		$this->send( $data );
		$this->send( "." );

		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative respose to the DATA command: {$resp}" );

		return true;
	}

	public function reset()
	{
		$this->send( "RSET" );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the RSET command: {$resp}" );

		return true;
	}

	public function noop()
	{
		$this->send( "NOOP" );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the NOOP command: {$resp}" );

		return true;
	}

	public function quit()
	{
		$this->send( "QUIT" );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 221 ) === false )
			throw new SmtpException( "The server returned a negative response to the QUIT command: {$resp}" );

		return true;
	}

	public function validateState()
	{
	}

	public function isServerCapable()
	{
	}
}
