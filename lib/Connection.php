<?php

namespace Mail;

abstract class Connection
{
	/**
	 * The CRLF sequence to send to the server after a command.
	 */
	const CRLF = "\r\n";

	/**
	 * The socket connection to the server.
	 *
	 * @var resource
	 * @access protected
	 */
	protected $socket = null;

	/**
	 * The greeting message from the server.
	 *
	 * @var string
	 * @access protected
	 */
	protected $greeting = null;

	/**
	 * The host name or IP address of the POP3 server.
	 *
	 * @var string
	 * @access protected
	 */
	protected $host = null;

	/**
	 * The port of the POP3 server.
	 *
	 * @var int
	 */
	protected $port = null;

	/**
	 * The transport method for the socket connection.
	 *
	 * @var string
	 * @access protected
	 */
	protected $transport = 'tcp';

	/**
	 * The timeout in seconds for the socket.
	 *
	 * @var int
	 * @access protected
	 */
	protected $timeout = 30;

	/**
	 * Public constructor.
	 *
	 * @param string $host
	 * @param string $port
	 * @param string transport
	 * @param int $timeout
	 * @throws ConnectionException
	 *         if the hostname, port, transport or timeout is not
	 *         defined.
	 */
	public function __construct( $host, $port, $transport = 'tcp', $timeout = 30 )
	{
		if ( $host === null )
			throw new ConnectionException( "The hostname is not defined." );
		if ( $port === null )
			throw new ConnectionException( "The port is not defined." );
		if ( $transport === null )
			throw new ConnectionException( "The transport is not defined." );
		if ( $timeout === null )
			throw new ConnectionException( "The timeout is not defined." );

		$this->host = $host;
		$this->port = $port;
		$this->transport = $transport;
		$this->timeout = $timeout;
	}

	/**
	 * Connect to the POP3 server.
	 *
	 * @throws ConnectionException
	 *         if the connection is already established
	 *         or if PHP does not have the openssl extension loaded
	 *         or if PHP failed to connect to the POP3 server
	 *         or if a negative response from the POP3 server was
	 *         received.
	 */
	public function connect()
	{
		if ( $this->isConnected() === true )
			throw new ConnectionException( "The connection is already established." );
		if ( ( $this->transport === 'ssl' || $this->transport === 'tls' ) && extension_loaded( 'openssl' ) === false )
			throw new ConnectionException( "PHP does not have the openssl extension loaded." );

		$errno = null;
		$errstr = null;

		// Check if SSL is enabled.
		if ( $this->transport === 'ssl' )
			$this->socket = @fsockopen( "ssl://{$this->host}:{$this->port}", $errno, $errstr, $timeout );
		else
			$this->socket = @fsockopen( "tcp://{$this->host}:{$this->port}", $errno, $errstr, $timeout );

		// Check if connection was established.
		if ( $this->isConnected() === false )
			throw new ConnectionException( "Failed to connect to server: {$this->host}:{$this->port}.");

		$this->greeting = $this->getResponse();

		if ( $this->isResponseOK( $this->greeting ) === false )
			throw new ConnectionException( "Negative response from the server was received: '{$this->greeting}'" );
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
	 * Get the response from the POP3 server.
	 *
	 * @throws ConnectionException
	 *         if PHP failed to read resp from the socket.
	 * @returns string
	 */
	protected function getResponse( $trim = false )
	{
		if ( $this->isConnected() === true ) {
			$buf = '';
			$resp = '';

			while( strpos( $resp, self::CRLF ) === false ) {
				$buf = fgets( $this->socket, 512 );

				if ( $buf === false ) {
					$this->close();
					throw new ConnectionException( "Failed to read resp from the socket." );
				}

				$resp .= $buf;
			}

			if ( $trim === false )
				return $resp;
			else
				return rtrim( $resp, self::CRLF );
		}
	}

	/**
	 * Sends a request the POP3 server.
	 *
	 * @param string $data
	 * @throws ConnectionException
	 *         if PHP failed to write to the socket.
	 */
	public function send( $data )
	{
		if ( $this->isConnected() === true )
			if ( fwrite( $this->socket, $data . self::CRLF, strlen( $data . self::CRLF ) ) === false )
				throw new ConnectionException( "Failed to write to the socket." );
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
	 * Public destructor.
	 * 
	 * Closes the connection to the POP3 server.
	 */
	public function __destruct()
	{
		$this->close();
	}

	/**
	 * Start TLS negotiation on the current connection.
	 *
	 * Returns true if the TLS connection was successfully
	 * established.
	 *
	 * @throws ConnectionException
	 *         if the server returned a negative response to the STLS
	 *         (starttls) command
	 *         or if the TLS negotiation has failed.
	 * @returns bool
	 */
	protected function starttls()
	{
		if ( stream_socket_enable_crypto( $this->socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT ) == false )
			throw new ConnectionException( "The TLS negotiation has failed." );

		return true;
	}
}

class ConnectionException extends \Exception {}
