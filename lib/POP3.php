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
	const STATE_UPDATE = 3;

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
		{
			throw new POPException( "The hostname is not defined." );
		}
		if ( $port === null )
		{
			throw new POP3Exception( "The port is not defined." );
		}
	
		$errno = null;
		$errstr = null;

		// Check if SSL is enabled.
		if ( $ssl === true ) {
			$this->conn = @fsockopen( "ssl://{$host}:{$port}", $errno, $errstr, $timeout );
		}
		else
		{
			$this->conn = @fsockopen( "tcp://{$host}:{$port}", $errno, $errstr, $timeout );
		}
	
		// Check if connection was established.
		if ( $this->isConnected() === false )
		{
			throw new POP3Exception( "Failed to connect to server: {$host}:{$port}.");
		}

		$this->greeting = $this->recvLn();

		if ( $this->isResponseOK( $this->greeting ) === false )
		{
			throw new POP3Exception( "Negative response from the server was received: '{$this->greeting}'." );
		}

		$this->state = self::STATE_AUTHORIZATION;
	}

	public function getCapabilities()
	{
		if ( $this->state !== self::STATE_NOT_CONNECTED )
		{
			$this->send( "CAPA" );
			$resp = $this->recvLn();

			if ( $this->isResponseOK( $resp ) !== true )
			{
				throw new POP3Exception( "The server received a negative response to the CAPA command: {$resp}." );
			}

			$data = null;
			while ( $resp = $this->recvLn() )
			{
				if ( $this->isTerminationOctet( $resp ) === true )
				{
					break;
				}
	
				$data .= $resp;
			}
	
			return $data;
		}
	}

	public function authenticate( $username, $password )
	{
		$this->validateState( self::STATE_AUTHORIZATION, 'USER' );

		$this->send( "USER {$username}" );
		$resp = $this->recvLn();

		if ( $this->isResponseOK( $resp ) === false )
		{
			throw new POP3Exception( "The username is not valid: {$resp}." );
		}

		$this->send( "PASS {$password}" );
		$resp = $this->recvLn();

		if ( $this->isResponseOK( $resp ) === false )
		{
			throw new POP3Exception(" The password is not valid: {$resp}." );
		}

		$this->state = self::STATE_TRANSACTION;
	}

	public function status()
	{
		// TODO: Parse drop listing.
		
		$this->validateState( self::STATE_TRANSACTION, 'STAT' );

		$this->send( "STAT" );
		$resp = $this->recvLn();

		if ( $this->isResponseOK( $resp ) === false )
		{
			throw new POP3Exception( "The server did not respond with a status message: {$resp}." );
		}
			
		return $resp;
	}

	public function listMessages( $msg = null )
	{
		// TODO: Return an array of the scan listing.
		// TODO: LIST with argument does not work. There is no termination octet.
	
		$this->validateState( self::STATE_TRANSACTION, 'LIST' );

		if ( $msg !== null )
		{
			$this->send( "LIST {$msg}" );
		}
		else
		{
			$this->send( "LIST" );
		}
	
		$resp = $this->recvLn();

		if ( $this->isResponseOK( $resp ) === false )
		{
			throw new POP3Exception( "The server did not respond with a scan listing: {$resp}." );
		}

		$data = null;
		while ( $resp = $this->recvLn() )
		{
			if ( $this->isTerminationOctet( $resp ) === true )
			{
				break;
			}

			$data .= $resp;
		}

		return $data;
	}

	public function retrieve( $msg )
	{
		$this->validateState( self::STATE_TRANSACTION, 'RETR' );

		if ( $msg === null )
		{
			throw new POP3Exception( "A message number is required by the RETR command." );
		}

		$this->send( "RETR {$msg}" );
		$resp = $this->recvLn();

		if ( $this->isResponseOK( $resp ) === false )
		{
			throw new POP3Exception( "The server sent a negative response to the RETR command: {$resp}." );
		}

		$data = null;
		while ( $resp = $this->recvLn() )
		{
			if ( $this->isTerminationOctet( $resp ) === true )
			{
				break;
			}

			$data .= $resp;
		}

		return $data;
	}

	public function delete( $msg )
	{
		$this->validateState( self::STATE_TRANSACTION, 'DELE' );

		if ( $msg === null )
		{
			throw new POP3Exception( "A message number is required by the DELE command." );
		}

		$this->send( "DELE {$msg}" );
		$resp = $this->recvLn();

		if ( $this->isResponseOK( $resp ) === false )
		{
			throw new POP3Exception( "The server sent a negative response to the DELE command: {$resp}." );
			return false;
		}

		return true;
	}

	public function noop()
	{
		$this->validateState( self::STATE_TRANSACTION, 'NOOP' );

		$this->send( "NOOP" );
		$resp = $this->recvLn();

		if ( $this->isResponseOK( $resp ) === false )
		{
			throw new POP3Exception( "The server sent a negative response to the NOOP command: {$resp}." );
			return false;
		}

		return true;
	}

	public function reset()
	{
		$this->validateState( self::STATE_TRANSACTION, 'RSET' );

		$this->send( "RSET" );
		$resp = $this->recvLn();

		if ( $this->isResponseOK( $resp ) === false )
		{
			throw new POP3Exception( "The server sent a negative response to the RSET command: {$resp}." );
		}

		return true;
	}

	public function top( $msg, $lines = 0 )
	{
		$this->validateState( self::STATE_TRANSACTION, 'TOP' );
	
		if ( $msg === null )
		{
			throw new POP3Exception( "A message number is required by the TOP command." );
		}

		if ( $lines === null )
		{
			throw new POP3Exception( "A number of lines is required by the TOP command." );
		}

		$this->send( "TOP {$msg} {$lines}" );
		$resp = $this->recvLn();

		if ( $this->isResponseOK( $resp ) === false )
		{
			throw new POP3Exception( "The server sent a negative response to the RETR command: {$resp}." );
		}

		$data = null;
		while ( $resp = $this->recvLn() )
		{
			if ( $this->isTerminationOctet( $resp ) === true )
			{
				break;
			}

			$data .= $resp;
		}

		return $data;
	}

	public function uidl( $msg = null )
	{
		// TODO: Return an array of the scan listing.
		// TODO: UIDL with argument does not work. There is no termination octet.
		$this->validateState( self::STATE_TRANSACTION, 'UIDL' );
	
		if ( $msg != null )
		{
			$this->send( "UIDL {$msg}" );
		}
		else
		{
			$this->send( "UIDL" );
		}
	
		$resp = $this->recvLn();

		if ( $this->isResponseOK( $resp ) === false )
		{
			throw new POP3Exception( "The server did not respond with a scan listing: {$resp}." );
		}

		$data = null;
		while ( $resp = $this->recvLn() )
		{
			if ( $this->isTerminationOctet( $resp ) === true )
			{
				break;
			}

			$data .= $resp;
		}

		return $data;
	}

	
	public function quit()
	{
		if ( $this->state !== self::STATE_NOT_CONNECTED )
		{
			$this->state = self::STATE_UPDATE;
	
			$this->send( "QUIT" );
			$resp = $this->recvLn();
			
			if ( $this->isResponseOK( $resp ) === false )
			{
				throw new POP3Exception( "The server sent a negative response to the QUIT command: {$resp}." );
			}
	
			$this->close();
			$this->state = self::STATE_NOT_CONNECTED;
	
			return true;
		}
	}

	public function close()
	{
		if ( $this->isConnected() )
		{
			fclose( $this->conn );
			$this->conn = null;
		}
	}

	public function send( $data )
	{
		if ( $this->isConnected() === true )
		{
			if ( fwrite( $this->conn, $data . self::CRLF, strlen( $data . self::CRLF ) ) === false )
			{
				throw new POP3Exception( "Failed to write to the socket." );
			}
		}
	}

	private function recvLn()
	{
		if ( $this->isConnected() === true )
		{
			$line = '';
			$data = '';

			while( strpos( $data, self::CRLF ) === false )
			{
				$line = fgets( $this->conn, 512 );

				if ( $line === false )
				{
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
		{
			return true;
		}

		return false;
	}
	
	private function isTerminationOctet( $resp )
	{
		if ( strpos( rtrim( $resp, self::CRLF ), self::TERMINATION_OCTET ) === 0  )
		{
			return true;
		}

		return false;
	}


	public function getCurrentStateName()
	{
		if ( $this->state === self::STATE_NOT_CONNECTED )
		{
			return "STATE_NOT_CONNECTED";
		}
		if ( $this->state === self::STATE_AUTHORIZATION )
		{
			return "STATE_AUTHORIZATION";
		}
		if ( $this->state === self::STATE_TRANSACTION )
		{
			return "STATE_TRANSACTION";
		}
		if ( $this->state === self::STATE_UPDATE )
		{
			return "STATE_UPDATE";
		}
	}

	public function validateState( $valid_state, $cmd )
	{
		if ( $this->state !== $valid_state )
		{
			throw new POP3Exception( "This {$cmd} command is invalid for the current state: {$this->getCurrentStateName()}." );
		}
	}

	public function __destruct()
	{
		$this->close();
	}
}


class POP3Exception extends \Exception {}
