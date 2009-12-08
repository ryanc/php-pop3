<?php
/**
 * @author Ryan Cavicchioni <ryan@confabulator.net>
 * @copyright Copyright (c) 2009, Ryan Cavicchioni
 * @license http://www.opensource.org/licenses/bsd-license.php BSD Licnese
 * @todo Document the class.
 */

namespace Mail;

/**
 * The class POP3 can be used to access POP3 servers.
 *
 * @package POP3
 */
class POP3
{
	/**
	 * The CRLF sequence to send to the server after a command.
	 */
	const CRLF = "\r\n";

	/**
	 * The termination octet marks the end of a multiline response.
	 */
	const TERMINATION_OCTET = ".";

	/**
	 * The positive status indicator from the server.
	 */
	const RESP_OK = "+OK";

	/**
	 * The negative status indicator from the server.
	 */
	const RESP_ERR = "-ERR";

	// POP3 session states from RFC 1939. 

	/**
	 * POP3 session state when the client is not connected to the
	 * server.
	 */
	const STATE_NOT_CONNECTED = 0;

	/**
	 * POP3 session state when the client has connected to the server,
	 * the server sends a greeting and the client must identify
	 * itself.
	 */
	const STATE_AUTHORIZATION = 1;

	/**
	 * POP3 session state where the client has authenticated with the
	 * server and requests actions on part of the POP3 server.
	 */
	const STATE_TRANSACTION = 2;

	/**
	 * POP3 state when the client issues a QUIT command. Changes that
	 * the client made are not committed to the server.
	 */
	const STATE_UPDATE = 4;

	/**
	 * The socket connection to the server.
	 *
	 * @var resource
	 * @access private
	 */
	private $socket = null;

	/**
	 * The greeting message from the server.
	 *
	 * @var string
	 * @access private
	 */
	private $greeting = null;

	/**
	 * The host name or IP address of the POP3 server.
	 *
	 * @var string
	 * @access private
	 */
	private $host = null;

	/**
	 * The port of the POP3 server.
	 *
	 * @var int
	 * @access private
	 */
	private $port = null;

	/**
	 * The transport method for the socket connection.
	 *
	 * @var string
	 * @access private
	 */
	private $transport = 'tcp';

	/**
	 * The timeout in seconds for the socket.
	 *
	 * @var int
	 * @access private
	 */
	private $timeout = 30;

	/**
	 * The username used to authenticate with the POP3 server.
	 *
	 * @var string
	 * @access private
	 */
	private $user = null;

	/**
	 * The password used to authenticate with the POP3 server.
	 *
	 * @var string
	 * @access private
	 */
	private $password = null;

	/**
	 * The current POP3 session state of the server.
	 *
	 * @var int Use self::STATE_NOT_CONNECTED,
	 *              self::STATE_AUTHORIZATION,
	 *              self::STATE_TRANSACTION,
	 *           OR self::STATE_UPDATE
	 * @access protected
	 */
	protected $state = self::STATE_NOT_CONNECTED;

	/**
	 * Public constructor.
	 *
	 * @param string $host
	 * @param string $port
	 * @param string transport
	 * @param int $timeout
	 * @throws POP3Exception
	 *         if the hostname, port, transport or timeout is not
	 *         defined.
	 */
	public function __construct( $host, $port, $transport = 'tcp', $timeout = 30 )
	{
		if ( $host === null )
			throw new POP3Exception( "The hostname is not defined." );
		if ( $port === null )
			throw new POP3Exception( "The port is not defined." );
		if ( $transport === null )
			throw new POP3Exception( "The transport is not defined." );
		if ( $timeout === null )
			throw new POP3Exception( "The timeout is not defined." );

		$this->host = $host;
		$this->port = $port;
		$this->transport = $transport;
		$this->timeout = $timeout;

		$this->state = self::STATE_NOT_CONNECTED;
	}

	/**
	 * Connect to the POP3 server.
	 *
	 * @throws POP3Exception
	 *         if the connection is already established
	 *         or if PHP does not have the openssl extension loaded
	 *         or if PHP failed to connect to the POP3 server
	 *         or if a negative response from the POP3 server was
	 *         received.
	 */
	public function connect()
	{
		if ( $this->isConnected() === true )
			throw new POP3Exception( "The connection is already established." );
		if ( ( $this->transport === 'ssl' || $this->transport === 'tls' ) && extension_loaded( 'openssl' ) === false )
			throw new POP3Exception( "PHP does not have the openssl extension loaded." );

		$errno = null;
		$errstr = null;

		// Check if SSL is enabled.
		if ( $this->transport === 'ssl' )
			$this->socket = @fsockopen( "ssl://{$this->host}:{$this->port}", $errno, $errstr, $timeout );
		else
			$this->socket = @fsockopen( "tcp://{$this->host}:{$this->port}", $errno, $errstr, $timeout );
	
		// Check if connection was established.
		if ( $this->isConnected() === false )
			throw new POP3Exception( "Failed to connect to server: {$this->host}:{$this->port}.");

		$this->greeting = $this->getResponse();

		if ( $this->isResponseOK( $this->greeting ) === false )
			throw new POP3Exception( "Negative response from the server was received: '{$this->greeting}'." );

		$this->state = self::STATE_AUTHORIZATION;

		if ( $this->transport === 'tls' )
			$this->starttls();
	}
	
	/**
	 * Retrieve the capabilities of the POP3 server.
	 *
	 * @param string $format
	 * @returns array
	 */
	public function getServerCapabilities( $format )
	{
		$this->validateState( self::STATE_AUTHORIZATION | self:: STATE_TRANSACTION, 'CAPA' );

		$this->send( "CAPA" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) !== true )
			throw new POP3Exception( "The server returned a negative response to the CAPA command: {$resp}." );

		$data = array();
		while ( $resp = $this->getResponse() ) {
			if ( $this->isTerminationOctet( $resp ) === true )
				break;

			$data[] = rtrim( $resp );
		}

		if ( $format === 'raw' )
			return implode( $data, self::CRLF );

		return $data;
	}

	/**
	 * Start TLS negotiation on the current connection.
	 *
	 * Returns true if the TLS connection was successfully
	 * established.
	 *
	 * @throws POP3Exception
	 *         if the server returned a negative response to the STLS
	 *         (starttls) command
	 *         or if the TLS negotiation has failed.
	 * @returns bool
	 */
	private function starttls()
	{
		$this->isServerCapable( "STLS" );

		$this->validateState( self::STATE_AUTHORIZATION, 'STLS' );

		$this->send( "STLS" );
		$resp = $this->getResponse();
		
		if ( $this->isResponseOK( $resp ) !== true )
			throw new POP3Exception( "The server returned a negative response to the STLS command: {$resp}." );

		if ( stream_socket_enable_crypto( $this->socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT ) == false )
			throw new POP3Exception( "The TLS negotiation has failed." );

		return true;
	}

	/**
	 * Authenticate the user to the server.
	 * 
	 * @param string $username
	 * @param string $password
	 * @throws POP3Exception
	 *         if the username or password is not valid.
	 * @todo Disable insecure authentication.
	 */
	public function authenticate( $username, $password )
	{
		$this->validateState( self::STATE_AUTHORIZATION, 'USER' );

		$this->send( "USER {$username}" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The username is not valid: {$resp}." );

		$this->send( "PASS {$password}" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception(" The password is not valid: {$resp}." );

		$this->state = self::STATE_TRANSACTION;
	}
	
	/**
	 * Issues the STAT command to the server and returns a drop
	 * listing.
	 *
	 * @throws POP3Exception
	 *         if the server did not respond with a status message.
	 * @returns array
	 */
	public function status()
	{
		$this->validateState( self::STATE_TRANSACTION, 'STAT' );

		$this->send( "STAT" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server did not respond with a status message: {$resp}." );
		
		sscanf( $resp, "+OK %d %d", $msgno, $size );
		$maildrop = array( 'messages' => (int) $msgno, 'size' => (int) $size );

		return $maildrop;
	}
	
	/**
	 * Issues the LIST command to the server and returns a scan
	 * listing.
	 *
	 * @param int $msgno
	 * @throws POP3Exception
	 *         if the server did not respond with a scan listing.
	 * @returns array
	 */
	public function listMessages( $msgno = null )
	{
		$this->validateState( self::STATE_TRANSACTION, 'LIST' );

		if ( $msgno !== null )
			$this->send( "LIST {$msgno}" );
		 else
			$this->send( "LIST" );
	
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server did not respond with a scan listing: {$resp}." );
		
		if ( $msgno !== null ) {
			sscanf( $resp, "+OK %d %s", $id, $size );
			return array( 'id' => $id, 'size' => $size );
		}

		$data = null;
		while ( $resp = $this->getResponse() ) {
			if ( $this->isTerminationOctet( $resp ) === true )
				break;
			
			list( $msgno, $size ) = explode( ' ', rtrim( $resp ) );
			$data[(int)$msgno] = (int)$size;
		}

		return $data;
	}

	/**
	 * Issues the RETR command to the server and returns the contents
	 * of a message.
	 *
	 * @param int $msgno
	 * @throws POP3Exception
	 *         if the message id is not defined
	 *         or if the server returns a negative response to the
	 *         RETR command.
	 * @returns string
	 */
	public function retrieve( $msgno )
	{
		$this->validateState( self::STATE_TRANSACTION, 'RETR' );

		if ( $msgno === null )
			throw new POP3Exception( "A message number is required by the RETR command." );

		$this->send( "RETR {$msgno}" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server sent a negative response to the RETR command: {$resp}." );

		$data = null;
		while ( $resp = $this->getResponse() ) {
			if ( $this->isTerminationOctet( $resp ) === true )
				break;

			$data .= $resp;
		}

		return $data;
	}
	
	/**
	 * Deletes a message from the POP3 server.
	 *
	 * @param int $msgno
	 * @throws POP3Exception
	 *         if the message id is not defined
	 *         or if the returns a negative response to the DELE
	 *         command.
	 * @returns bool
	 */
	public function delete( $msgno )
	{
		$this->validateState( self::STATE_TRANSACTION, 'DELE' );

		if ( $msgno === null )
			throw new POP3Exception( "A message number is required by the DELE command." );

		$this->send( "DELE {$msgno}" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server sent a negative response to the DELE command: {$resp}." );

		return true;
	}
	
	/**
	 * The POP3 server does nothing, it mearly replies with a positive
	 * response.
	 * 
	 * @throws POP3Exception
	 *         if the server returns a negative response to the NOOP
	 *         command.
	 * @returns bool
	 */
	public function noop()
	{
		$this->validateState( self::STATE_TRANSACTION, 'NOOP' );

		$this->send( "NOOP" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server sent a negative response to the NOOP command: {$resp}." );

		return true;
	}

	/**
	 * Resets the changes made in the POP3 session.
	 *
	 * @throws POP3Exception
	 *         if the server returns a negative response to the
	 *         RSET command.
	 * @returns bool
	 */
	public function reset()
	{
		$this->validateState( self::STATE_TRANSACTION, 'RSET' );

		$this->send( "RSET" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server sent a negative response to the RSET command: {$resp}." );

		return true;
	}
	
	/**
	 * Returns the headers of $msgno if $lines is not given. If $lines
	 * if given, the POP3 server will respond with the headers and
	 * then the specified number of lines from the message's body.
	 *
	 * @param int $msgno
	 * @param int $lines
	 * @throws POP3Exception
	 *         if the message id is not defined
	 *         or if the number of lines is not defined
	 *         of if the server returns a negative response to the TOP
	 *         command.
	 * @returns string
	 */
	public function top( $msgno, $lines = 0 )
	{
		$this->isServerCapable( "TOP" );

		$this->validateState( self::STATE_TRANSACTION, 'TOP' );
	
		if ( $msgno === null )
			throw new POP3Exception( "A message number is required by the TOP command." );

		if ( $lines === null )
			throw new POP3Exception( "A number of lines is required by the TOP command." );

		$this->send( "TOP {$msgno} {$lines}" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server sent a negative response to the TOP command: {$resp}." );

		$data = null;
		while ( $resp = $this->getResponse() ) {
			if ( $this->isTerminationOctet( $resp ) === true )
				break;

			$data .= $resp;
		}

		return $data;
	}
	
	/**
	 * Issues the UIDL command to the server and returns a unique-id
	 * listing.
	 *
	 * @param int $msgno
	 * @throws POP3Exception
	 *         if the server returns a negative response to the UIDL
	 *         command.
	 * @returns array
	 */
	public function uidl( $msgno = null )
	{
		$this->isServerCapable( "UIDL" );

		$this->validateState( self::STATE_TRANSACTION, 'UIDL' );
	
		if ( $msgno !== null )
			$this->send( "UIDL {$msgno}" );
		else
			$this->send( "UIDL" );
	
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server did not respond with a scan listing: {$resp}." );

		if ( $msgno !== null ) {
			sscanf( $resp, "+OK %d %s", $id, $uid );
			return array( 'id' => (int) $id, 'uid' => $uid );
		}

		$data = null;
		while ( $resp = $this->getResponse() ) {
			if ( $this->isTerminationOctet( $resp ) === true )
				break;
			list( $msgno, $uid ) = explode( ' ', rtrim( $resp ) );
			$data[(int)$msgno] = $uid;
		}

		return $data;
	}

	/**
	 * Issues the QUIT command to the server and enters the UPDATE
	 * state.
	 *
	 * @throws POP3Exception
	 *         if the server returns a negative response to the QUIT
	 *         command.
	 * @returns bool
	 */
	public function quit()
	{
		$this->validateState( self::STATE_AUTHORIZATION | self::STATE_TRANSACTION, 'QUIT' );

		$this->state = self::STATE_UPDATE;

		$this->send( "QUIT" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server sent a negative response to the QUIT command: {$resp}." );

		$this->close();
		$this->state = self::STATE_NOT_CONNECTED;

		return true;
	}
	
	/**
	 * Closes the connection to the POP3 server.
	 */
	public function close()
	{
		if ( $this->isConnected() ) {
			fclose( $this->socket );
			$this->socket = null;
		}
	}
	
	/**
	 * Sends a request the POP3 server.
	 *
	 * @param string $data
	 * @throws POPException
	 *         if PHP failed to write to the socket.
	 */
	public function send( $data )
	{
		if ( $this->isConnected() === true )
			if ( fwrite( $this->socket, $data . self::CRLF, strlen( $data . self::CRLF ) ) === false )
				throw new POP3Exception( "Failed to write to the socket." );
	}
	
	/**
	 * Get the response from the POP3 server.
	 *
	 * @throws POP3Exception
	 *         if PHP failed to read data from the socket.
	 * @returns string
	 */
	private function getResponse()
	{
		if ( $this->isConnected() === true ) {
			$line = '';
			$data = '';

			while( strpos( $data, self::CRLF ) === false ) {
				$line = fgets( $this->socket, 512 );

				if ( $line === false ) {
					$this->close();
					throw new POP3Exception( "Failed to read data from the socket." );
				}

				$data .= $line;
			}

			return $data;
		}
	}
	
	/**
	 * Returns true if connected to the POP3 server.
	 * @returns bool
	 */
	public function isConnected()
	{
		return is_resource( $this->socket );
	}
	
	/**
	 * Determines if the server issued a positive or negative
	 * response.
	 *
	 * @param string $resp
	 * @returns bool
	 */
	private function isResponseOK( $resp )
	{
		if ( strpos( $resp, self::RESP_OK ) === 0 )
			return true;

		return false;
	}
	
	/**
	 * Determine if a multiline response contains the termination
	 * octet.
	 *
	 * @param string $resp
	 * @returns bool
	 */
	private function isTerminationOctet( $resp )
	{
		if ( strpos( rtrim( $resp, self::CRLF ), self::TERMINATION_OCTET ) === 0  )
			return true;

		return false;
	}

	/**
	 * Returns the current session state name for exception messages.
	 *
	 * @returns string
	 */
	public function getCurrentStateName()
	{
		if ( $this->state === self::STATE_NOT_CONNECTED )
			return "STATE_NOT_CONNECTED";
		if ( $this->state === self::STATE_AUTHORIZATION )
			return "STATE_AUTHORIZATION";
		if ( $this->state === self::STATE_TRANSACTION )
			return "STATE_TRANSACTION";
		if ( $this->state === self::STATE_UPDATE )
			return "STATE_UPDATE";
	}

	/**
	 * Determines if the server is capable of the given command.
	 *
	 * @param string $cmd
	 * @throws POP3Exception
	 *         if the server is not capable of the command.
	 */
	public function isServerCapable( $cmd )
	{
		if ( in_array( $cmd, $this->getServerCapabilities( 'array' ) ) === true )
			return true;
		else
			throw new POP3Exception( "The server does not support the {$cmd} command." );
	}
	
	/**
	 * Determines if the current state is valid for the given command.
	 *
	 * @param int $valid_state
	 * @param string $cmd
	 * @throws POP3Exception
	 *         if the command if not valid for the current state.
	 */
	public function validateState( $valid_state, $cmd )
	{
		if ( ( $valid_state & $this->state ) == 0 )
			throw new POP3Exception( "This {$cmd} command is invalid for the current state: {$this->getCurrentStateName()}." );
	}

	/**
	 * Public destructor.
	 * 
	 * Closes the connection to the POP3 server.
	 */
	public function __destruct()
	{
		$this->close();
	}
}
