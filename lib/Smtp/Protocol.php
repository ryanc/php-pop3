<?php

namespace Mail\Protocol;
use Mail\Connection;

class Smtp extends Connection
{
	const STATE_NOT_CONNECTED = 0;
	const STATE_CONNECTED = 1;
	const STATE_AUTHENTICATED = 2;

	private $_username = null;
	private $_password = null;

	public function connect()
	{
		parent::connect();

		if ( $this->_transport === 'tls' )
			$this->_starttls();
	}

	protected function _starttls()
	{
		$this->_send( "STARTTLS" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 220 ) === false )
			throw new SmtpException( "The server returned a negative response to the STARTTLS command: {$resp}" );

		parent::_starttls();

		return true;
	}

	public function authenticate( $username, $password, $method = 'plain' )
	{
		$this->username = $username;
		$this->password = $password;

		if ( strtolower( $method ) === 'plain' )
			$status = $this->_authPlain();
		elseif ( strtolower( $method ) === 'login' )
			$status = $this->_authLogin();
		else
			throw new SmtpException( "Invalid authentication method." );

		return $status;
	}

	private function _authPlain()
	{
		// Validate session state.
		$auth_string = base64_encode( "\0{$this->username}\0{$this->password}" );

		$this->_send( "AUTH PLAIN {$auth_string}" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 235 ) === false )
			throw new SmtpException( "Authentication failed: ${resp}" );

		return true;
	}

	private function _authLogin()
	{
		$this->_send( "AUTH LOGIN" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 334 ) === false )
			throw new SmtpException( "The server returned a negative response to the AUTH LOGIN command: {$resp}" );

		$this->_send( base64_encode( $this->username ) );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 334 ) === false )
			throw new SmtpException( "The server did not accept the username: {$resp}" );

		$this->_send( base64_encode( $this->password ) );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 235 ) === false )
			throw new SmtpException( "The server did not accept the password: {$resp}" );

		return true;
	}

	protected function _isGreetingOK( $resp )
	{
		if ( strpos( $resp, "220" ) === 0 )
			return true;

		return false;
	}

	protected function _isResponseOK( $resp, $expect )
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
		$this->_send( "HELO {$hostname}" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the HELO command: {$resp}" );

		return true;
	}

	public function ehlo( $hostname = 'localhost' )
	{
		$buf = array();
		$this->_send( "EHLO {$hostname}" );

		do {
			$resp = $this->_getResponse( true );

			if ( $this->_isResponseOK( $resp, 250 ) === false )
				throw new SmtpException( "The server returned a negative response to the EHLO command: {$resp}" );

			$buf[] = ltrim( $resp, "250- " );
		} while ( strpos( $resp, '-' ) === 3 );

		return $buf;
	}

	public function mail ( $from )
	{
		$this->_send( "MAIL FROM: <{$from}>" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the MAIL command: {$resp}" );

		return true;
	}

	public function rcpt ( $to )
	{
		$this->_send( "RCPT TO: <{$to}>" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, array( 250, 251 ) ) === false )
			throw new SmtpException( "The server returned a negative response to the RCPT command: {$resp}" );

		return true;
	}

	public function data ( $data )
	{
		$this->_send( "DATA" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 354 ) === false )
			throw new SmtpException( "The server returned a negative response to the DATA command: {$resp}" );

		$this->_send( $data );
		$this->_send( "." );

		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative respose to the DATA command: {$resp}" );

		return true;
	}

	public function reset()
	{
		$this->_send( "RSET" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the RSET command: {$resp}" );

		return true;
	}

	public function noop()
	{
		$this->_send( "NOOP" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the NOOP command: {$resp}" );

		return true;
	}

	public function quit()
	{
		$this->_send( "QUIT" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 221 ) === false )
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
