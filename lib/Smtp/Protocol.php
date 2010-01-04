<?php
/**
 * @author Ryan Cavicchioni <ryan@confabulator.net>
 * @copyright Copyright (c) 2009, Ryan Cavicchioni
 * @license http://www.opensource.org/licenses/bsd-license.php BSD Licnese
 * @todo Document the class.
 */

namespace Mail\Protocol;
use Mail\Connection;

/**
 * The class Smtp can be used to access SMTP servers.
 */
class Smtp extends Connection
{
	/**
	 * SMTP session state when the client is not connected to the
	 * server
	 */
	const STATE_NOT_CONNECTED = 0;

	/**
	 * SMTP session state when the client is connected to the server.
	 */
	const STATE_CONNECTED = 1;

	/**
	 * SMTP session state when the client has authenticated to the
	 * server.
	 */
	const STATE_AUTHENTICATED = 2;

	/**
	 * The username used to authenticate to the SMTP server.
	 *
	 * @var string
	 */
	private $_username = null;

	/**
	 * The password used to authenticate to the SMTP server.
	 *
	 * @var string
	 */
	private $_password = null;

	/**
	 * The capabilities of the SMTP server which are populated by the
	 * EHLO command.
	 *
	 * @var array
	 */
	private $_capabilities = array();

	/**
	 * The current POP3 session state of the server.
	 *
	 * @var int Use self::STATE_NOT_CONNECTED,
	 *              self::STATE_CONNECTED,
	 *           OR self::STATE_AUTHENTICATED
	 */
	private $_state = self::STATE_NOT_CONNECTED;

	/**
	 * Connect to the SMTP server.
	 *
	 * @throws ConnectionException
	 *         if the connection is already established
	 *         or if PHP does not have the openssl extension loaded
	 *         or if PHP failed to connect to the SMTP server
	 *         or if a negative response from the SMTP server was
	 *         received.
	 */
	public function connect()
	{
		parent::connect();

		if ( $this->_transport === 'tls' )
			$this->_starttls();

		$this->_state = self::STATE_CONNECTED;
	}

	/**
	 * Start TLS negotiation on the current connection.
	 *
	 * Returns true if the TLS connection was successfully
	 * established.
	 *
	 * @throws SmtpException
	 *         if the server returned a negative response.
	 * @throws ConnectionException
	 *         if the TLS negotiation has failed.
	 * @return bool
	 */
	protected function _starttls()
	{
		$this->_send( "STARTTLS" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 220 ) === false )
			throw new SmtpException( "The server returned a negative response to the STARTTLS command: {$resp}" );

		parent::_starttls();

		return true;
	}

	/**
	 * Authenticate the user to the SMTP server.
	 *
	 * @param string $username
	 * @param string $password
	 * @param string $method 'login' or 'plain'
	 * @throws SmtpException
	 *         if an invalid authentication method is used.
	 * @return bool
	 */
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

		$this->_state = self::STATE_AUTHENTICATED;

		return $status;
	}

	/**
	 * Authenticate using the PLAIN mechanism.
	 *
	 * @throws SmtpException
	 *         if authentication fails.
	 * @return bool
	 */
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

	/**
	 * Authenticate using the LOGIN mechanism.
	 *
	 * @throws SmtpException
	 *         if the server returns a negative response
	 *         or if authentication fails.
	 * @return bool
	 */
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

	/**
	 * Determine if the server greeting is positive or negative.
	 *
	 * @param string $resp
	 * @return bool
	 */
	protected function _isGreetingOK( $resp )
	{
		if ( strpos( $resp, "220" ) === 0 )
			return true;

		return false;
	}

	/**
	 * Determine if the server responds with the expected SMTP status
	 * code.
	 *
	 * @param string $resp
	 * @param string $expect
	 * @return bool
	 */
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

	/**
	 * Issue the HELO command to the server.
	 *
	 * @param string $hostname
	 * @throws SmtpException
	 *         if the server returns a negative response.
	 * @return bool
	 */
	public function helo( $hostname = 'localhost' )
	{
		$this->_send( "HELO {$hostname}" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the HELO command: {$resp}" );

		return true;
	}

	/**
	 * Issue the EHLO command to the server and return its
	 * capabilities.
	 *
	 * @param string $hostname
	 * @throws SmtpException
	 *         if the server returns a negative response.
	 * @return array
	 */
	public function ehlo( $hostname = 'localhost' )
	{
		$this->_send( "EHLO {$hostname}" );

		do {
			$resp = $this->_getResponse( true );

			if ( $this->_isResponseOK( $resp, 250 ) === false )
				throw new SmtpException( "The server returned a negative response to the EHLO command: {$resp}" );

			$this->_capabilities[] = ltrim( $resp, "250- " );
		} while ( strpos( $resp, '-' ) === 3 );

		return $this->_capabilities;
	}

	/**
	 * Issue the MAIL FROM command to the server.
	 *
	 * @param string $from
	 * @throws SmtpException
	 *         if the server returns a negative response.
	 * @return bool
	 */
	public function mail ( $from )
	{
		$this->_send( "MAIL FROM: <{$from}>" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the MAIL command: {$resp}" );

		return true;
	}

	/**
	 * Issue the RCPT TO command to the server.
	 *
	 * @param string $to
	 * @throws SmtpException
	 *         if the server returns a negative response.
	 * @return bool
	 */
	public function rcpt ( $to )
	{
		$this->_send( "RCPT TO: <{$to}>" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, array( 250, 251 ) ) === false )
			throw new SmtpException( "The server returned a negative response to the RCPT command: {$resp}" );

		return true;
	}

	/**
	 * Issue the DATA command to the server.
	 * @param string $data
	 * @throws SmtpException
	 *         if the server returns a negative response.
	 * @return bool
	 */
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

	/**
	 * Abort the current mail transaction.
	 *
	 * @throws SmtpException
	 *         if the server returns a negative response.
	 * @return bool
	 */
	public function reset()
	{
		$this->_send( "RSET" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the RSET command: {$resp}" );

		return true;
	}

	/**
	 * The SMTP server does nothing, it mearly replies with a positive
	 * response.
	 *
	 * @throws SmtpException
	 *         if the server returns a negative response.
	 * @return bool
	 */
	public function noop()
	{
		$this->_send( "NOOP" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, 250 ) === false )
			throw new SmtpException( "The server returned a negative response to the NOOP command: {$resp}" );

		return true;
	}

	/**
	 * Verify that $username is a valid user or mailbox.
	 *
	 * @param string $username
	 * @return bool
	 */
	public function vrfy( $username )
	{
		$this->_isServerCapable( "VRFY" );

		$this->_send( "VRFY {$username}" );
		$resp = $this->_getResponse( true );

		if ( $this->_isResponseOK( $resp, array( 250, 251, 252 ) ) === false )
			return false;

		return true;
	}

	/**
	 * Quits the SMTP transaction.
	 *
	 * @throws SmtpException
	 *         if the server returns a negative response.
	 * @return bool
	 */
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

	/**
	 * Verify that the server is capable of the given command.
	 *
	 * @param string $cmd
	 * @throws SmtpException
	 *         if the server does not support the given command.
	 * @return bool
	 */
	private function _isServerCapable( $cmd )
	{
		if ( empty( $this->_capabilities ) === true )
			$this->ehlo();

		if ( in_array( $cmd, $this->_capabilities ) === false )
			throw new SmtpException( "The server does not support the {$cmd} command." );

		return true;
	}
}
