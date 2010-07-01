<?php
/**
 * MailKit
 *
 * @package MailKit
 * @author Ryan Cavicchioni <ryan@confabulator.net>
 * @copyright Copyright (c) 2009-2010, Ryan Cavicchioni
 * @license http://www.opensource.org/licenses/bsd-license.php BSD Licnese
 */

namespace Mail\Protocol;
use Mail\Connection;

/**
 * The class POP3 can be used to access POP3 servers.
 *
 * @package MailKit
 * @author Ryan Cavicchioni <ryan@confabulator.net>
 * @copyright Copyright (c) 2009-2010, Ryan Cavicchioni
 * @license http://www.opensource.org/licenses/bsd-license.php BSD Licnese
 */
class Pop3 extends Connection
{

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
	 * the server _sends a greeting and the client must identify
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
	 * The username used to authenticate with the POP3 server.
	 *
	 * @var string
	 * @access private
	 */
	private $_username = null;

	/**
	 * The password used to authenticate with the POP3 server.
	 *
	 * @var string
	 * @access private
	 */
	private $_password = null;

	/**
	 * The capabilities of the POP3 server which are populated by the
	 * CAPA command.
	 *
	 * @var array
	 */
	private $_capabilities = array();

	/**
	 * The current POP3 session state of the server.
	 *
	 * @var int Use self::STATE_NOT_CONNECTED,
	 *				self::STATE_AUTHORIZATION,
	 *				self::STATE_TRANSACTION,
	 *			 OR self::STATE_UPDATE
	 * @access protected
	 */
	protected $_state = self::STATE_NOT_CONNECTED;

	/**
	 * Connect to the POP3 server.
	 *
	 * @throws Pop3_Exception
	 *		   if the connection is already established
	 *		   or if PHP does not have the openssl extension loaded
	 *		   or if PHP failed to connect to the POP3 server
	 *		   or if a negative response from the POP3 server was
	 *		   received.
	 */
	public function connect()
	{
		parent::connect();

		$this->_state = self::STATE_AUTHORIZATION;

		if ($this->_transport === 'tls') {
			$this->_starttls();
		}
	}

	/**
	 * Retrieve the capabilities of the POP3 server.
	 *
	 * @param string $format
	 * @return array
	 */
	public function get_server_capabilities($format = 'array')
	{
		$this->_log->debug('POP3: Retrieving server capabilities');
		$this->_validate_state(self::STATE_AUTHORIZATION | self::STATE_TRANSACTION, 'CAPA');

		$this->_send("CAPA");
		$resp = $this->_get_response();

		if ($this->_is_response_ok($resp) !== true) {
			throw new Pop3_Exception("The server returned a negative response to the CAPA command: {$resp}.");
		}

		while ($resp = $this->_get_response()) {
			if ($this->_is_termination_octet($resp) === true) {
				break;
			}

			$this->_capabilities[] = rtrim($resp);
		}

		if ($format === 'raw') {
			return implode($this->_capabilities, self::CRLF);
		}

		return $this->_capabilities;
	}

	/**
	 * Start TLS negotiation on the current connection.
	 *
	 * Returns true if the TLS connection was successfully
	 * established.
	 *
	 * @throws Pop3_Exception
	 *		   if the server returned a negative response to the STLS
	 *		   (STARTTLS) command
	 *		   or if the TLS negotiation has failed.
	 * @return bool
	 */
	protected function _starttls()
	{
		$this->_log->debug('POP3: Sending the STLS command. ');
		$this->_is_server_capable("STLS");

		$this->_validate_state(self::STATE_AUTHORIZATION, 'STLS');

		$this->_send("STLS");
		$resp = $this->_get_response();

		if ($this->_is_response_ok($resp) !== true) {
			throw new Pop3_Exception("The server returned a negative response to the STLS command: {$resp}");
		}

		parent::_starttls();

		return true;
	}

	/**
	 * Authenticate the user to the server.
	 *
	 * @param string $username
	 * @param string $password
	 * @param string $method 'login' or 'plain'
	 * @throws Pop3_Exception
	 *		   if an invalid authentication method is used.
	 * @return bool
	 * @todo Disable insecure authentication.
	 */
	public function authenticate($username, $password, $method = 'plain')
	{
		$this->_validate_state(self::STATE_AUTHORIZATION, 'USER');

		$this->_username = $username;
		$this->_password = $password;

		if (strtolower($method) === 'plain') {
			$status = $this->_auth_plain();
		}
		elseif (strtolower($method) === 'login') {
			$status = $this->_auth_login();
		}
		else {
			throw new Pop3_Exception("Invalid authentication method.");
		}

		$this->_state = self::STATE_TRANSACTION;

		return $status;
	}

	/**
	 * Authenticate using the PLAIN mechanism.
	 *
	 * @throws Pop3_Exception
	 *		   if authentication fails.
	 * @return bool
	 */
	private function _auth_plain()
	{
		$this->_log->debug('POP3: Authenticating to the server via the PLAIN mechanism.');
		$this->_send("USER {$this->_username}");
		$resp = $this->_get_response(true);

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The username is not valid: {$resp}");
		}

		$this->_send("PASS {$this->_password}");
		$resp = $this->_get_response(true);

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The password is not valid: {$resp}");
		}

		return true;
	}

	/**
	 * Authenticate using the LOGIN mechanism.
	 *
	 * @throws Pop3_Exception
	 *		   if the server returns a negative response
	 *		   or if authentication fails.
	 * @return bool
	 */
	private function _auth_login()
	{
		$this->_log->debug('POP3: Authenticating to the server via the LOGIN mechanism.');
		$this->_send("AUTH LOGIN");
		$resp = $this->_get_response(true);

		if (strpos($resp, "+") === false) {
			throw new Pop3_Exception("The server returned a negative response to the AUTH LOGIN command: {$resp}");
		}

		$this->_send(base64_encode($this->_username));
		$resp = $this->_get_response(true);

		if (strpos($resp, "+") === false) {
			throw new Pop3_Exception("The username is not valid: {$resp}");
		}

		$this->_send(base64_encode($this->_password));
		$resp = $this->_get_response(true);

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The password is not valid: {$resp}");
		}

		return true;
	}

	/**
	 * Issues the STAT command to the server and returns a drop
	 * listing.
	 *
	 * @throws Pop3_Exception
	 *		   if the server did not respond with a status message.
	 * @return array
	 */
	public function status()
	{
		$this->_log->debug('POP3: Sending the STAT command.');
		$this->_validate_state(self::STATE_TRANSACTION, 'STAT');

		$this->_send("STAT");
		$resp = $this->_get_response();

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The server did not respond with a status message: {$resp}");
		}

		sscanf($resp, "+OK %d %d", $msgno, $size);
		$maildrop = array('messages' => (int) $msgno, 'size' => (int) $size);

		return $maildrop;
	}

	/**
	 * Issues the LIST command to the server and returns a scan
	 * listing.
	 *
	 * @param int $msgid
	 * @throws Pop3_Exception
	 *		   if the server did not respond with a scan listing.
	 * @return array
	 */
	public function list_messages($msgid = null)
	{
		$this->_log->debug('POP3: Sending the LIST command.');
		$this->_validate_state(self::STATE_TRANSACTION, 'LIST');

		if ($msgid !== null) {
			$this->_send("LIST {$msgid}");
		}
		else {
			$this->_send("LIST");
		}

		$resp = $this->_get_response();

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The server did not respond with a scan listing: {$resp}");
		}

		if ($msgid !== null) {
			sscanf($resp, "+OK %d %s", $id, $size);
			return array('id' => $id, 'size' => $size);
		}

		$messages = null;
		while ($resp = $this->_get_response()) {
			if ($this->_is_termination_octet($resp) === true) {
				break;
			}

			list($msgid, $size) = explode(' ', rtrim($resp));
			$messages[(int)$msgid] = (int)$size;
		}

		return $messages;
	}

	/**
	 * Issues the RETR command to the server and returns the contents
	 * of a message.
	 *
	 * @param int $msgid
	 * @throws Pop3_Exception
	 *		   if the message id is not defined
	 *		   or if the server returns a negative response to the
	 *		   RETR command.
	 * @return string
	 */
	public function retrieve($msgid)
	{
		$this->_log->debug('POP3: Sending the RETR command.');
		$this->_validate_state(self::STATE_TRANSACTION, 'RETR');

		if ($msgid === null) {
			throw new Pop3_Exception("A message number is required by the RETR command.");
		}

		$this->_send("RETR {$msgid}");
		$resp = $this->_get_response();

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The server sent a negative response to the RETR command: {$resp}");
		}

		$message = null;
		while ($resp = $this->_get_response()) {
			if ($this->_is_termination_octet($resp) === true) {
				break;
			}

			$message .= $resp;
		}

		return $message;
	}

	/**
	 * Deletes a message from the POP3 server.
	 *
	 * @param int $msgid
	 * @throws Pop3_Exception
	 *		   if the message id is not defined
	 *		   or if the returns a negative response to the DELE
	 *		   command.
	 * @return bool
	 */
	public function delete($msgid)
	{
		$this->_log->debug('POP3: Sending the DELE command.');
		$this->_validate_state(self::STATE_TRANSACTION, 'DELE');

		if ($msgid === null) {
			throw new Pop3_Exception("A message number is required by the DELE command.");
		}

		$this->_send("DELE {$msgid}");
		$resp = $this->_get_response();

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The server sent a negative response to the DELE command: {$resp}");
		}

		return true;
	}

	/**
	 * The POP3 server does nothing, it mearly replies with a positive
	 * response.
	 *
	 * @throws Pop3_Exception
	 *		   if the server returns a negative response to the NOOP
	 *		   command.
	 * @return bool
	 */
	public function noop()
	{
		$this->_log->debug('POP3: Sending the NOOP command.');
		$this->_validate_state(self::STATE_TRANSACTION, 'NOOP');

		$this->_send("NOOP");
		$resp = $this->_get_response();

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The server sent a negative response to the NOOP command: {$resp}");
		}

		return true;
	}

	/**
	 * Resets the changes made in the POP3 session.
	 *
	 * @throws Pop3_Exception
	 *		   if the server returns a negative response to the
	 *		   RSET command.
	 * @return bool
	 */
	public function reset()
	{
		$this->_log->debug('POP3: Sending the RSET command.');
		$this->_validate_state(self::STATE_TRANSACTION, 'RSET');

		$this->_send("RSET");
		$resp = $this->_get_response();

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The server sent a negative response to the RSET command: {$resp}");
		}

		return true;
	}

	/**
	 * Returns the headers of $msgid if $lines is not given. If $lines
	 * if given, the POP3 server will respond with the headers and
	 * then the specified number of lines from the message's body.
	 *
	 * @param int $msgid
	 * @param int $lines
	 * @throws Pop3_Exception
	 *		   if the message id is not defined
	 *		   or if the number of lines is not defined
	 *		   of if the server returns a negative response to the TOP
	 *		   command.
	 * @return string
	 */
	public function top($msgid, $lines = 0)
	{
		$this->_log->debug('POP3: Sending the TOP command. ');
		$this->_is_server_capable("TOP");

		$this->_validate_state(self::STATE_TRANSACTION, 'TOP');

		if ($msgid === null) {
			throw new Pop3_Exception("A message number is required by the TOP command.");
		}

		if ($lines === null) {
			throw new Pop3_Exception("A number of lines is required by the TOP command.");
		}

		$this->_send("TOP {$msgid} {$lines}");
		$resp = $this->_get_response();

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The server sent a negative response to the TOP command: {$resp}");
		}

		$message = null;
		while ($resp = $this->_get_response()) {
			if ($this->_is_termination_octet($resp) === true) {
				break;
			}

			$message .= $resp;
		}

		return $message;
	}

	/**
	 * Issues the UIDL command to the server and returns a unique-id
	 * listing.
	 *
	 * @param int $msgid
	 * @throws Pop3_Exception
	 *		   if the server returns a negative response to the UIDL
	 *		   command.
	 * @return array
	 */
	public function uidl($msgid = null)
	{
		$this->_log->debug('POP3: Sending the UIDL command.');
		$this->_is_server_capable("UIDL");

		$this->_validate_state(self::STATE_TRANSACTION, 'UIDL');

		if ($msgid !== null) {
			$this->_send("UIDL {$msgid}");
		}
		else {
			$this->_send("UIDL");
		}

		$resp = $this->_get_response();

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The server did not respond with a scan listing: {$resp}");
		}

		if ($msgid !== null) {
			sscanf($resp, "+OK %d %s", $id, $uid);
			return array('id' => (int) $id, 'uid' => $uid);
		}

		$unique_id = null;
		while ($resp = $this->_get_response()) {
			if ($this->_is_termination_octet($resp) === true) {
				break;
			}

			list($msgid, $uid) = explode(' ', rtrim($resp));
			$unique_id[(int)$msgid] = $uid;
		}

		return $unique_id;
	}

	/**
	 * Issues the QUIT command to the server and enters the UPDATE
	 * state.
	 *
	 * @throws Pop3_Exception
	 *		   if the server returns a negative response to the QUIT
	 *		   command.
	 * @return bool
	 */
	public function quit()
	{
		$this->_log->debug('POP3: Sending the QUIT command.');
		$this->_validate_state(self::STATE_AUTHORIZATION | self::STATE_TRANSACTION, 'QUIT');

		$this->_state = self::STATE_UPDATE;

		$this->_send("QUIT");
		$resp = $this->_get_response();

		if ($this->_is_response_ok($resp) === false) {
			throw new Pop3_Exception("The server sent a negative response to the QUIT command: {$resp}");
		}

		$this->close();
		$this->_state = self::STATE_NOT_CONNECTED;

		return true;
	}

	/**
	 * Determines if the server issued a positive or negative
	 * response.
	 *
	 * @param string $resp
	 * @return bool
	 */
	protected function _is_response_ok($resp)
	{
		if (strpos($resp, self::RESP_OK) === 0) {
			return true;
		}

		return false;
	}

	/**
	 * Determine if the server greeting is positive or negative.
	 *
	 * @param string $resp
	 * @return bool
	 */
	protected function _is_greeting_ok($resp)
	{
		return $this->_is_response_ok($resp);
	}

	/**
	 * Determine if a multiline response contains the termination
	 * octet.
	 *
	 * @param string $resp
	 * @return bool
	 */
	private function _is_termination_octet($resp)
	{
		if (strpos(rtrim($resp, self::CRLF), self::TERMINATION_OCTET) === 0 ) {
			return true;
		}

		return false;
	}

	/**
	 * Returns the current session state name for exception messages.
	 *
	 * @return string
	 */
	private function _state_to_string($state)
	{
		$state_map = array(
			self::STATE_NOT_CONNECTED => 'STATE_NOT_CONNECTED',
			self::STATE_AUTHORIZATION => 'STATE_AUTHORIZATION',
			self::STATE_TRANSACTION   => 'STATE_TRANSACTION',
			self::STATE_UPDATE		  => 'STATE_UPDATE'
	   );

		return $state_map[$state];
	}

	/**
	 * Determines if the server is capable of the given command.
	 *
	 * @param string $cmd
	 * @throws Pop3_Exception
	 *		   if the server is not capable of the command.
	 */
	private function _is_server_capable($cmd)
	{
		if (empty($this->_capabilities) === true) {
			$this->get_server_capabilities();
		}

		if (in_array($cmd, $this->_capabilities) === false) {
			throw new Pop3_Exception("The server does not support the {$cmd} command.");
		}

		return true;
	}

	/**
	 * Determines if the current state is valid for the given command.
	 *
	 * @param int $valid_state
	 * @param string $cmd
	 * @throws Pop3_Exception
	 *		   if the command if not valid for the current state.
	 */
	protected function _validate_state($valid_state, $cmd)
	{
		if (($valid_state & $this->_state) == 0) {
			throw new Pop3_Exception("This {$cmd} command is invalid for the current state: {$this->_state_to_string($this->_state)}.");
		}
	}
}
