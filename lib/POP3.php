<?php
namespace Mail;

class POP3
{
	const CRLF = "\r\n";
	const TERMINATION_OCTET = ".";

	const RESP_OK = "+OK";
	const RESP_ERR = "-ERR";

	// POP3 session states from RFC 1939. 
	const STATE_NOT_CONNECTED = 0;
	const STATE_AUTHORIZATION = 1;
	const STATE_TRANSACTION = 2;
	const STATE_UPDATE = 4;

	private $conn = null;
	private $greeting = null;

	protected $state = self::STATE_NOT_CONNECTED;

	public function __construct()
	{
		
	}

	public function connect( $host, $port, $ssl = false, $timeout = 30 )
	{
		// TODO: Implement other transports, such as TLS.
		// Validate arguments.
		if ( $host === null )
			throw new POP3Exception( "The hostname is not defined." );
		if ( $port === null )
			throw new POP3Exception( "The port is not defined." );
	
		$errno = null;
		$errstr = null;

		// Check if SSL is enabled.
		if ( $ssl === true )
			$this->conn = @fsockopen( "ssl://{$host}:{$port}", $errno, $errstr, $timeout );
		else
			$this->conn = @fsockopen( "tcp://{$host}:{$port}", $errno, $errstr, $timeout );
	
		// Check if connection was established.
		if ( $this->isConnected() === false )
			throw new POP3Exception( "Failed to connect to server: {$host}:{$port}.");

		$this->greeting = $this->getResponse();

		if ( $this->isResponseOK( $this->greeting ) === false )
			throw new POP3Exception( "Negative response from the server was received: '{$this->greeting}'." );

		$this->state = self::STATE_AUTHORIZATION;
	}

	public function getCapabilities( $format )
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

	public function starttls()
	{
		$this->isServerCapable( "STLS" );

		$this->validateState( self::STATE_AUTHORIZATION, 'STLS' );

		$this->send( "STLS" );
		$resp = $this->getResponse();
		
		if ( $this->isResponseOK( $resp ) !== true )
			throw new POP3Exception( "The server returned a negative response to the STLS command: {$resp}." );

		if ( stream_socket_enable_crypto( $this->conn, true, STREAM_CRYPTO_METHOD_TLS_CLIENT ) == false )
			throw new POP3Exception( "The TLS negotiation has failed." );

		return true;
	}

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

	public function status()
	{
		// TODO: Parse drop listing.
		
		$this->validateState( self::STATE_TRANSACTION, 'STAT' );

		$this->send( "STAT" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server did not respond with a status message: {$resp}." );
			
		return $resp;
	}

	public function listMessages( $msgno = null )
	{
		// TODO: Return an array of the scan listing.
		// TODO: LIST with argument does not work. There is no termination octet.
	
		$this->validateState( self::STATE_TRANSACTION, 'LIST' );

		if ( $msgno !== null )
			$this->send( "LIST {$msgno}" );
		 else
			$this->send( "LIST" );
	
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server did not respond with a scan listing: {$resp}." );

		$data = null;
		while ( $resp = $this->getResponse() ) {
			if ( $this->isTerminationOctet( $resp ) === true )
				break;

			$data .= $resp;
		}

		return $data;
	}

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

	public function noop()
	{
		$this->validateState( self::STATE_TRANSACTION, 'NOOP' );

		$this->send( "NOOP" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server sent a negative response to the NOOP command: {$resp}." );

		return true;
	}

	public function reset()
	{
		$this->validateState( self::STATE_TRANSACTION, 'RSET' );

		$this->send( "RSET" );
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server sent a negative response to the RSET command: {$resp}." );

		return true;
	}

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
			throw new POP3Exception( "The server sent a negative response to the RETR command: {$resp}." );

		$data = null;
		while ( $resp = $this->getResponse() ) {
			if ( $this->isTerminationOctet( $resp ) === true )
				break;

			$data .= $resp;
		}

		return $data;
	}

	public function uidl( $msgno = null )
	{
		// TODO: Return an array of the scan listing.
		// TODO: UIDL with argument does not work. There is no termination octet.
		$this->isServerCapable( "UIDL" );

		$this->validateState( self::STATE_TRANSACTION, 'UIDL' );
	
		if ( $msgno !== null )
			$this->send( "UIDL {$msgno}" );
		else
			$this->send( "UIDL" );
	
		$resp = $this->getResponse();

		if ( $this->isResponseOK( $resp ) === false )
			throw new POP3Exception( "The server did not respond with a scan listing: {$resp}." );

		$data = null;
		while ( $resp = $this->getResponse() ) {
			if ( $this->isTerminationOctet( $resp ) === true )
				break;

			$data .= $resp;
		}

		return $data;
	}

	
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

	public function close()
	{
		if ( $this->isConnected() ) {
			fclose( $this->conn );
			$this->conn = null;
		}
	}

	public function send( $data )
	{
		if ( $this->isConnected() === true )
			if ( fwrite( $this->conn, $data . self::CRLF, strlen( $data . self::CRLF ) ) === false )
				throw new POP3Exception( "Failed to write to the socket." );
	}

	private function getResponse()
	{
		if ( $this->isConnected() === true ) {
			$line = '';
			$data = '';

			while( strpos( $data, self::CRLF ) === false ) {
				$line = fgets( $this->conn, 512 );

				if ( $line === false ) {
					$this->close();
					throw new POP3Exception( "Failed to read data from the socket." );
				}

				$data .= $line;
			}

			return $data;
		}
	}

	public function isConnected()
	{
		return is_resource( $this->conn );
	}
	
	private function isResponseOK( $resp )
	{
		if ( strpos( $resp, self::RESP_OK ) === 0 )
			return true;

		return false;
	}
	
	private function isTerminationOctet( $resp )
	{
		if ( strpos( rtrim( $resp, self::CRLF ), self::TERMINATION_OCTET ) === 0  )
			return true;

		return false;
	}


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

	public function isServerCapable( $cmd )
	{
		if ( in_array( $cmd, $this->getCapabilities( 'array' ) ) === true )
			return true;
		else
			throw new POP3Exception( "The server does not support the {$cmd} command." );
	}

	public function validateState( $valid_state, $cmd )
	{
		if ( ( $valid_state & $this->state ) == 0 )
			throw new POP3Exception( "This {$cmd} command is invalid for the current state: {$this->getCurrentStateName()}." );
	}

	public function __destruct()
	{
		$this->close();
	}
}


class POP3Exception extends \Exception {}
