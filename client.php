<?php
ini_set('date.timezone','Asia/Shanghai');
class AES {
	public $localIV;
	public $encryptKey;
	
	public function encrypt($str) {
		return openssl_encrypt($str, 'AES-256-CFB', $this->encryptKey, 0, $this->localIV);
	}
	public function decrypt($str) {
		return openssl_decrypt($str, 'AES-256-CFB', $this->encryptKey, 0, $this->localIV);
	}
}
class Client extends Thread {
	
	public $socket;
	public $host;
	public $port;
	public $heartbeat;
	
	public function send($data) {
		if(!$this->socket) {
			echo "Error\n";
		}
		if((time() - $this->heartbeat) > 10) {
			echo date("[H:i:s] ") . "警告：心跳数据包超时，连接可能已断开。\n";
		}
		fwrite($this->socket, $data."\n");
	}
	
	public function run() {
		echo date("[H:i:s] ") . "正在连接服务器...\n";
		$first_connect = true;
		while(true) {
			$this->socket = stream_socket_client("udp://{$this->host}:{$this->port}", $errno, $errstr);
			if(!$this->socket) {
				echo date("[H:i:s] ") . "连接到服务器失败！\n";
			} else {
				if($first_connect) {
					echo date("[H:i:s] ") . "已连接服务器：{$this->host}:{$this->port}\n";
					$first_connect = false;
				}
			}
			$this->send(json_encode(Array(
				'type' => 'heartbeat'
			)));
			while($data = fread($this->socket, 8192)) {
				$msg = json_decode($data, true);
				if($msg) {
					if(isset($msg['type'])) {
						switch($msg['type']) {
							case "message":
								if(isset($msg['username']) && isset($msg['message']) && $msg['time']) {
									$msg_decrypt = json_decode($this->aes->decrypt($msg['message']), true);
									if($msg_decrypt) {
										if($this->protect) {
											if($msg_decrypt['timestamp'] == date("YmdHi")) {
												echo date("[H:i:s]", $msg['time']) . "<{$msg['username']}> {$msg_decrypt['data']}\n";
												$this->count++;
											} elseif(isset($msg_decrypt['timestamp'])) {
												echo date("[H:i:s] ") . "警告：可能有人正在尝试对您进行数据包重放攻击，或者是对方电脑时间与您不同步。\n";
											}
										} else {
											echo date("[H:i:s]", $msg['time']) . "<{$msg['username']}> {$msg_decrypt['data']}\n";
										}
									}
								}
								break;
							case "heartbeat":
								$this->send(json_encode(Array(
									'type' => 'heartbeat'
								)));
								$this->heartbeat = time();
								break;
						}
					}
				} else {
					echo "Fail decode: " . $data . "\n";
				}
			}
			echo date("[H:i:s] ") . "与服务器的连接意外断开，3s 后重新连接...\n";
			sleep(3);
		}
	}
}
if(isset($argv[1])) {
	if(file_exists($argv[1])) {
		$json = json_decode(@file_get_contents($argv[1]), true);
		if(isset($json['host']) && isset($json['port']) && isset($json['user']) && isset($json['pass']) && isset($json['protect'])) {
			$host = $json['host'];
			$port = $json['port'];
			$user = $json['user'];
			$pass = $json['pass'];
			$protect = $json['protect'];
		} else {
			echo "无效的配置文件 {$argv[1]}。\n";
		}
	}
}
while($user == "" || $pass == "" || $host == "" || $port == "") {
	echo "服务器地址> ";
	$host = trim(fgets(STDIN));
	echo "服务器端口> ";
	$port = trim(fgets(STDIN));
	echo "显示昵称> ";
	$user = trim(fgets(STDIN));
	echo "消息密钥> ";
	$pass = trim(fgets(STDIN));
	echo "开启防数据包重放攻击功能可以防止恶意攻击，使用时间验证，请确保其他人的电脑时间与您相差不超过一分钟。\n";
	echo "开启后其他人也必须要启用此功能，如果对方未开启此功能，您只能向对方发送单向消息。\n";
	echo "是否开启此功能？(y/n)> ";
	$protect = trim(fgets(STDIN));
	if(strtolower($protect) == "y") {
		$protect = true;
	} else {
		$protect = false;
	}
	echo "是否保存此连接？(y/n)> ";
	$saveConnect = trim(fgets(STDIN));
	if(strtolower($saveConnect) == "y") {
		$saveName = "";
		while(!preg_match("/^[A-Za-z0-9\_\-\.]+$/", $saveName)) {
			echo "请输入配置文件名(只能包含 A-Za-z0-9_-.)> ";
			$saveName = trim(fgets(STDIN));
		}
		if(file_exists($saveName)) {
			echo "文件 {$saveName} 已存在，是否覆盖？(y/n)> ";
			$override = trim(fgets(STDIN));
			if(strtolower($override) == "y") {
				file_put_contents($saveName, json_encode(Array(
					'host' => $host,
					'port' => $port,
					'user' => $user,
					'pass' => $pass,
					'protect' => $protect
				)));
				echo "配置文件保存成功。\n";
			}
		} else {
			file_put_contents($saveName, json_encode(Array(
				'host' => $host,
				'port' => $port,
				'user' => $user,
				'pass' => $pass,
				'protect' => $protect
			)));
			echo "配置文件保存成功。\n";
		}
	}
}
$aes = new AES();
$aes->encryptKey = md5(sha1($password));
$aes->localIV = substr(md5($aes->encryptKey), 0, 16);
$Client = new Client();
$Client->host = $host;
$Client->port = $port;
$Client->aes = $aes;
$Client->protect = $protect;
$Client->start();
echo "客户端已开始运行，您可以直接输入消息内容来发送。\n";
while(true) {
	$input = trim(fgets(STDIN));
	if($protect) {
		$sendData = Array(
			'data' => $input,
			'timestamp' => date("YmdHi")
		);
	} else {
		$sendData = Array(
			'data' => $input
		);
	}
	$Client->send(json_encode(Array(
		'username' => $user,
		'type' => 'message',
		'message' => $aes->encrypt(json_encode($sendData)) . "\n"
	)));
}
