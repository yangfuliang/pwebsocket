<?php 

namespace Pwebsocket\Pwebsocket;

class Pwebsocket
{
	/**
	 * Socket name
	 * @var string
	 */
	private $_socketName = '';

	/**
	 * Context of socket
	 * @var resource
	 */
	private $_context = null;

	/**
	 * Socket
	 * @var resource
	 */
	static private $_socket = null;

	/**
	 * Base event
	 * @var resource
	 */
	static private $_eventBase = null;

	/**
	 * Read buffer size
	 * @var integer
	 */
	const READ_BUFFER_SIZE = 65535;

	/**
	 * connections
	 * @var array
	 */
	static private $_connections = array();

	/**
	 * buffers
	 * @var array
	 */
	static private $_buffers = array();

	/**
	 * handshakes
	 * @var array
	 */
	static private $_handshakes = array();

	/**
	 * Construct
	 * @param string $ip_address
	 * @param int 	 $port
	 */
	public function __construct($ip_address, $port) {
		if (empty($ip_address)) {
			throw new Exception("ip address error");
		}

		$this->_socketName = "tcp://{$ip_address}:{$port}";
	}

	/**
	 * Create Server
	 * @return Boolean
	 */
	private function createServer() {
		self::$_socket = stream_socket_server($this->_socketName, $errno, $errmsg);

		if (self::$_socket === FALSE) {
			throw new Exception($errmsg);
		}

		$socket = socket_import_stream(self::$_socket);

		socket_set_option($socket, SOL_SOCKET, SO_KEEPALIVE, 1);
		socket_set_option($socket, SOL_TCP, TCP_NODELAY, 1);

		stream_set_blocking(self::$_socket, 0);

		self::$_eventBase = event_base_new();
		$event = event_new();

		if (!event_set($event, self::$_socket, EV_READ | EV_PERSIST, array($this, "acceptConnection"))) {
			throw new Exception("Event Error");
		}

		if (!event_base_set($event, self::$_eventBase)) {
			throw new Exception("Event Error");
		}

		if (!event_add($event)) {
			throw new Exception("Event Error");
		}

		event_base_loop(self::$_eventBase);
	}

	private function acceptConnection() {
		$newSocket = stream_socket_accept(self::$_socket, 0, $remote_address);

		stream_set_blocking($newSocket, 0);
		$bufferSocket = event_buffer_new($newSocket, array($this, "eventRead"), NULL, array($this, "eventError"), (int)$newSocket);

		event_buffer_base_set($bufferSocket, self::$_eventBase);
		event_buffer_enable($bufferSocket, EV_READ | EV_PERSIST);

		self::$_connections[(int)$newSocket] = $newSocket;
    	self::$_buffers[(int)$bufferSocket] = $bufferSocket;
	}

	private function eventError($bufferSocket, $error, $newSocketId) {
		event_buffer_disable(self::$_buffers[(int)$bufferSocket], EV_READ | EV_WRITE);
	    event_buffer_free(self::$_buffers[(int)$bufferSocket]);
	    fclose(self::$_connections[$newSocketId]);
	    unset(self::$_buffers[(int)$bufferSocket], self::$_connections[$newSocketId], self::$_handshakes[$newSocketId]);
	}

	private function eventRead($bufferSocket, $newSocketId) {
		while ($buffer_read = event_buffer_read($bufferSocket, self::READ_BUFFER_SIZE)) {
			if ($buffer_read === '' OR $buffer_read === FALSE) {
				break;
			}

			if (!isset(self::$_handshakes[$newSocketId])) {
				$this->_handshakeHandle($bufferSocket, $buffer_read, $newSocketId);
				break;
			}

			if ($this->decode($buffer_read) === NULL) {
				break;
			}

			foreach (self::$_buffers as $value) {
				event_buffer_write($value, $this->encode($this->decode($buffer_read)));
			}
		}
	}

	private function _handshakeHandle($bufferSocket, $buffer_read, $newSocketId) {
		if (0 === strpos($buffer_read, "GET")) {
			$heder_end_pos = strpos($buffer_read, "\r\n\r\n");
            if (!$heder_end_pos) {
                return 0;
            }
            $header_length = $heder_end_pos + 4;

            $Sec_WebSocket_Key = '';
            if (preg_match("/Sec-WebSocket-Key: *(.*?)\r\n/i", $buffer_read, $match)) {
                $Sec_WebSocket_Key = $match[1];
            } else {
            	event_buffer_write($bufferSocket, "HTTP/1.1 400 Bad Request\r\n\r\n<b>400 Bad Request</b><br>Sec-WebSocket-Key not found.<br>This is a WebSocket service and can not be accessed via HTTP.");
            	event_buffer_disable(self::$_buffers[(int)$bufferSocket], EV_READ | EV_WRITE);
	    		event_buffer_free(self::$_buffers[(int)$bufferSocket]);
            	fclose(self::$_connections[$newSocketId]);
            	unset(self::$_buffers[(int)$bufferSocket], self::$_connections[$newSocketId]);
                return 0;
            }

            $new_key = base64_encode(sha1($Sec_WebSocket_Key . "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", true));

            $handshake_message  = "HTTP/1.1 101 Switching Protocols\r\n";
            $handshake_message .= "Upgrade: websocket\r\n";
            $handshake_message .= "Sec-WebSocket-Version: 13\r\n";
            $handshake_message .= "Connection: Upgrade\r\n";
            $handshake_message .= "Sec-WebSocket-Accept: " . $new_key . "\r\n\r\n";

            if (event_buffer_write($bufferSocket, $handshake_message) === FALSE) {
            	throw new Exception("handshake error");
            }

            self::$_handshakes[$newSocketId] = $bufferSocket;
		}
	}

	private function decode($message) {
		$decode = "";
		$opcode = ord(substr($message, 0, 1)) & 0x0F;
        $payloadlen = ord(substr($message, 1, 1)) & 0x7F;
        $ismask = (ord(substr($message, 1, 1)) & 0x80) >> 7;

        if ($ismask != 1 || $opcode == 0x8) {
            return null;
        }

        if ($payloadlen <= 125 && $payloadlen >= 0) {
            $maskkey = substr($message, 2, 4);
            $oridata = substr($message, 6);
        } else if ($payloadlen == 126) {
            $maskkey = substr($message, 4, 4);
            $oridata = substr($message, 8);
        } else if ($payloadlen == 127) {
            $maskkey = substr($message, 10, 4);
            $oridata = substr($message, 14);
        }

        $len = strlen($oridata);
        for($i = 0; $i < $len; $i++) {
            $decode .= $oridata[$i] ^ $maskkey[$i % 4];
        }

        return $decode;
	}

	private function encode($message) {
		$rsv1 = 0x0;
		$rsv2 = 0x0;
		$rsv3 = 0x0;
		$mask = 0x1;
		$length = strlen($message);
		$encode = chr((0x1 << 7) | ($rsv1 << 6) | ($rsv2 << 5) | ($rsv3 << 4) | 0x1);
		if(0xffff < $length) {
			$encode .= chr(0x7f) . pack('NN', 0, $length);
		} elseif(0x7d < $length) {
			$encode .= chr(0x7e) . pack('n', $length);
		} else {
			$encode .= chr($length);
		}

		$encode .= $message;
		return $encode;
	}

	public function run() {
		$this->createServer();
	}
}