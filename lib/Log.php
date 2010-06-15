<?php

class Log
{
    private static $_instance = null;

    private static $_logfile;
    private $_fh;
    private $_date_fmt = "M j, Y H:i:s";
    private $_log_fmt = "%s [%s] %s";

    const LF = "\n";

    // Error levels.
    const LOG_EMERGENCY = 0;
    const LOG_ALERT = 1;
    const LOG_CRITICAL = 2;
    const LOG_ERROR = 3;
    const LOG_WARNING = 4;
    const LOG_NOTICE = 5;
    const LOG_INFO = 6;
    const LOG_DEBUG = 7;

    private function __construct() {}

    public function __clone()
    {
        throw Exception( "Cloning is not supported." );
    }

    public static function singleton( $logfile )
    {
        if ( $logfile === null ) {
            throw new Log_Exception( "The log file path cannot be null." );
        }

        self::$_logfile = $logfile;

        if ( self::$_instance === null ) {
            $class = __CLASS__;
            self::$_instance = new $class;
        }
        
        return self::$_instance;
    } 

    public static function instance() {
        if( self::$_instance !== null ) {
            return self::$_instance;
        }
    }

    public function open()
    {
       $this->_fh = @fopen( self::$_logfile, 'a' );

       if ( $this->is_file_open() === false ) {
           throw new Log_Exception( "Cannot open the log file: {$logfile}" );
       }
    }

    public function write( $line )
    {
        $buf = sprintf( "%s%s", $line, self::LF );

        if ( fwrite( $this->_fh, $buf ) === false ) {
            throw new Log_Exception( "Error writing to log file." );
        }
    }

    public function close()
    {
        fclose( $this->_fh );
    }

    public function is_file_open()
    {
        if ( is_resource( $this->_fh ) === true ) {
            return true;
        }

        else {
            return false;
        }
    }

    public function priority_to_string( $priority )
    {
        $priority_map = array(
            self::LOG_EMERGENCY => 'emergency',
            self::LOG_ALERT     => 'alert',
            self::LOG_CRITICAL  => 'critical',
            self::LOG_ERROR     => 'error',
            self::LOG_WARNING   => 'warning',
            self::LOG_NOTICE    => 'notice',
            self::LOG_INFO      => 'info',
            self::LOG_DEBUG     => 'debug'
        );

        return $priority_map[$priority];
    }

    public function string_to_priority( $name )
    {
        $priority_map = array(
            'emergency' => self::LOG_EMERGENCY,
            'alert'     => self::LOG_ALERT,
            'critical'  => self::LOG_CRITICAL,
            'error'     => self::LOG_ERROR,
            'warning'   => self::LOG_WARNING,
            'notice'    => self::LOG_NOTICE,
            'info'      => self::LOG_INFO,
            'debug'     => self::LOG_DEBUG
        );

        return $priority_map[strtolower( $name )];
    }

    public function log( $priority, $line )
    {
        $date = new DateTime();
        $this->write( sprintf( $this->_log_fmt,
            $date->format( $this->_date_fmt),
            $this->priority_to_string( $priority ),
            $line
        ));
    }

    public function emerg( $line ) {
        $this->log( self::LOG_EMERGENCY, $line );
    }

    public function alert( $line ) {
        $this->log( self::LOG_ALERT, $line );
    }

    public function crit( $line ) {
        $this->log( self::LOG_CRITICAL, $line );
    }

    public function error( $line ) {
        $this->log( self::LOG_ERROR, $line );
    }

    public function warn( $line ) {
        $this->log( self::LOG_WARNING, $line );
    }

    public function notice( $line ) {
        $this->log( self::LOG_NOTICE, $line );
    }

    public function info( $line ) {
        $this->log( self::LOG_INFO, $line );
    }

    public function debug( $line ) {
        $this->log( self::LOG_DEBUG, $line );
    }

    public function __destruct()
    {
        if ( $this->is_file_open() === true ) {
            $this->close();
        }
    }
}

class Log_Exception extends Exception {}
