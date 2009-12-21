<?php

namespace Mail\Protocol;
use Mail\Connection;

class Smtp extends Connection
{
	const STATE_NOT_CONNECTED = 0;
	const STATE_CONNECTED = 1;
	const STATE_AUTHENTICATED = 2;

	private $username = null;
	private $password = null;

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

	public function authenticate( $username, $password, $method = 'PLAIN' )
	{
		$this->username = $username;
		$this->password = $password;

		if ( $method === 'PLAIN' )
			$status = $this->authPlain();
		elseif ( $method === 'LOGIN' )
			$status = $this->authLogin();

		return $status;
	}

	private function authPlain()
	{
		// Validate session state.
		$auth_string = base64_encode( "\0{$this->username}\0{$this->password}" );

		$this->send( "AUTH PLAIN {$auth_string}" );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 235 ) === false )
			throw new SmtpException( "Authentication failed: ${resp}" );

		return true;
	}

	private function authLogin()
	{
		$this->send( "AUTH LOGIN" );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 334 ) === false )
			throw new SmtpException( "The server returned a negative response to the AUTH LOGIN command: {$resp}" );

		$this->send( base64_encode( $this->username ) );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 334 ) === false )
			throw new SmtpException( "The server did not accept the username: {$resp}" );

		$this->send( base64_encode( $this->password ) );
		$resp = $this->getResponse( true );

		if ( $this->isResponseOK( $resp, 235 ) === false )
			throw new SmtpException( "The server did not accept the password: {$resp}" );

		return true;
	}

	protected function isGreetingOK( $resp )
	{
		if ( strpos( $resp, "220" ) === 0 )
			return true;

		return false;
	}

	protected function isResponseOK( $resp, $expect )
	{
		if ( is_array( $expect ) === true ) {
			$code = substr( $resp, 0, 3);
			if ( in_array( (int) $code, $expect ) === true )
				return true;
		}

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

		if ( $this->isResponseOK( $resp, array( 250, 251 ) ) === false )
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
