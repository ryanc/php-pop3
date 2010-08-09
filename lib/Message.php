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
    protected $_to = array();
    protected $_cc = array();
    protected $_bcc = array();
    protected $_from = null;
    protected $_returnPath = null;
    protected $_sender = null;
    public $replyTo = null;
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

    public static function newInstance()
    {
        return new self;
    }

    public function addTo($addr, $name = null)
    {
        array_push($this->_to, new Address($addr, $name));
        return $this;
    }

    public function addCc($addr, $name = null)
    {
        array_push($this->_cc, new Address($addr, $name));
        return $this;
    }

    public function addBcc($addr, $name = null)
    {
        array_push($this->_bcc, new Address($addr, $name));
        return $this;
    }

    public function setFrom($addr, $name = null)
    {
        $this->_from = new Address($addr, $name);
        return $this;
    }

    public function setReturnPath($addr)
    {
        $this->_returnPath = new Address($addr);
        return $this;
    }

    public function getTo()
    {
        return $this->_to;
    }

    public function getCc()
    {
        return $this->_cc;
    }

    public function getBcc()
    {
        return $this->_bcc;
    }

    public function getFrom()
    {
        return $this->_from;
    }

    public function getSender()
    {
        return $this->_sender;
    }
    
    public function getReturnPath()
    {
        return $this->_returnPath;
    }

    public function setSender($addr, $name = null)
    {
        $this->_sender = new Address($addr, $name);
        return $this;
    }

    public function setReplyTo($addr, $name = null)
    {
        $this->replyTo = new Address($addr, $name);
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
        if ($this->_from !== null) {
            $this->addHeader("From", (string) $this->_from);
        }
        if ($this->_sender !== null) {
            $this->addHeader("Sender", (string) $this->_sender);
        }
        if ($this->replyTo !== null) {
            $this->addHeader("Reply-To", (string) $this->reply_to);
        }
        if (count($this->_to)) {
            $this->addHeader("To", implode(", ", $this->_to));
        }
        if (count($this->_cc)) {
            $this->addHeader("Cc", implode(", ", $this->_cc));
        }
        if (count($this->_bcc)) {
            $this->addHeader("Bcc", implode(", ", $this->_cc));
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

    public function toString()
    {
        $buf = "";
        $this->_buildHeaders();

        foreach($this->headers as $name => $value) {
            $buf .=  sprintf("%s: %s%s", $name, $value, self::CRLF);
        }

        $buf .= self::CRLF;
        $buf .= $this->body;
        return $buf;
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
