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
	public $messageId = null;
	public $priority = null;
	public $userAgent = null;

	// Priorities for the X-Priority header.
	const PRIORITY_HIGHEST = 1;
	const PRIORITY_HIGH = 2;
	const PRIORITY_NORMAL = 3;
	const PRIORITY_LOW = 4;
	const PRIORITY_LOWEST = 5;

	const CRLF = "\r\n";

	public function addTo($addr, $name = null)
	{
		$this->to[] = new Address($addr, $name);
		return $this;
	}

	public function addCc($addr, $name = null)
	{
		$this->cc[] = new Address($addr, $name);
		return $this;
	}

	public function addBcc($addr, $name = null)
	{
		$this->bcc[] = new Address($addr, $name);
		return $this;
	}

	public function setFrom($addr, $name = null)
	{
		$this->from = new Address($addr, $name);
		return $this;
	}

	public function setSender($addr, $name = null)
	{
		$this->sender = new Address($addr, $name);
		return $this;
	}

	public function setReplyTo($addr, $name = null)
	{
		$this->reply_to = new Address($addr, $name);
		return $this;
	}

	public function setSubject($subject)
	{
		$this->subject = trim($subject);
		return $this;
	}

	public function setBody($body)
	{
		$this->body = trim($body);
		return $this;
	}

	public function setPriority($priority = 3)
	{
		$priorityMap = array(
			1 => 'Highest',
			2 => 'High',
			3 => 'Normal',
			4 => 'Low',
			5 => 'Lowest'
		);

		$pmapKeys = array_keys($priorityMap);

		if ($priority > 5) {
			$priority = max($pmapKeys);
		}

		elseif ($priority < 1) {
			$priority = min($pmapKeys);
		}

		$this->priority = sprintf("%d (%s)", $priority, $priorityMap[$priority]);

		return $this;
	}

	public function setUserAgent($userAgent)
	{
		$this->userAgent = $userAgent;
		return $this;
	}

	public function addHeader($name, $value)
	{
		$this->headers[$name] = $value;
	}

	private function getRandomId()
	{
		if (file_exists('/proc/sys/kernel/random/uuid') === true) {
			$fp = fopen('/proc/sys/kernel/random/uuid', 'r');
			$uuid = fread($fp, 36);
			fclose($fp);
			return $uuid;
		}

		elseif (function_exists('openssl_random_pseudo_bytes') === true) {
			$rand = openssl_random_pseudo_bytes(8);
			return sha1($rand);
		}

		elseif (file_exists('/dev/urandom') === true) {
			$fp = fopen('/dev/urandom', 'rb');
			$rand = fread($fp, 8);
			fclose($fp);
			return sha1($rand);
		}

		else {
			$id = sprintf("%s.%s.%s", date('YmdGms'), getmypid(), mt_rand());
			return $id;
		}
	}

	private function setMessageId()
	{
		$hostname = gethostname();

		$this->messageId = sprintf("<%s@%s>", $this->getRandomId(), $hostname);
	}

	private function _buildHeaders()
	{
		if ($this->from !== null) {
			$this->addHeader("From", (string) $this->from);
		}
		if ($this->sender !== null) {
			$this->addHeader("Sender", (string) $this->sender);
		}
		if ($this->reply_to !== null) {
			$this->addHeader("Reply-To", (string) $this->reply_to);
		}
		if (count($this->to)) {
			$this->addHeader("To", implode(", ", $this->to));
		}
		if (count($this->cc)) {
			$this->addHeader("Cc", implode(", ", $this->cc));
		}
		if (count($this->bcc)) {
			$this->addHeader("Bcc", implode(", ", $this->cc));
		}
		if ($this->priority !== null) {
			$this->addHeader("X-Priority", $this->priority);
		}
		if ($this->userAgent !== null) {
			$this->addHeader("User-Agent", $this->userAgent);
		}

		$this->addHeader("Subject", $this->subject);
		$this->addHeader("Date", date("r"));

		$this->setMessageId();

		$this->addHeader("Message-ID", $this->messageId);
	}

	private function _generateHeader()
	{
		$text = "";
		$this->_buildHeaders();

		foreach($this->headers as $name => $value) {
			$text .=  sprintf("%s: %s%s",	$name, $value, self::CRLF);
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

/**
 * Message Exception class.
 *
 * @package MailKit
 * @author Ryan Cavicchioni <ryan@confabulator.net>
 * @copyright Copyright (c) 2009-2010, Ryan Cavicchioni
 * @license http://www.opensource.org/licenses/bsd-license.php BSD Licnese
 */
class Message_Exception extends \Exception {}

/**
 * Email address class.
 *
 * @package MailKit
 * @author Ryan Cavicchioni <ryan@confabulator.net>
 * @copyright Copyright (c) 2009-2010, Ryan Cavicchioni
 * @license http://www.opensource.org/licenses/bsd-license.php BSD Licnese
 */
class Address
{
	public $name = null;
	public $email = null;

	public function __construct($email, $name = null)
	{
		$this->name = $name;
		$this->email = $email;
	}

	public function __toString()
	{
		if ($this->name !== null && $this->email !== null) {
			return sprintf("\"%s\" <%s>", $this->name, $this->email);
		}

		else {
			return sprintf("<%s>", $this->email);
		}
	}
}
