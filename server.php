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
$aes = new AES();
$aes->encryptKey = md5("TestKey");
$aes->localIV = substr(md5($aes->encryptKey), 0, 16);
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->set('client', '[]');
$server = new swoole_server("0.0.0.0", 9588, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
$server->redis = $redis;
$server->aes = $aes;
$server->on('Packet', function ($server, $data, $clientInfo) {
	// 获得所有客户端列表
	$client = json_decode($server->redis->get('client'), true);
	// 解析消息内容
	$message = json_decode($data, true);
	// 客户端名称
	$clientName = "{$clientInfo['address']}:{$clientInfo['port']}";
	if(!isset($client[$clientName])) {
		$client[$clientName] = Array(
			'host' => $clientInfo['address'],
			'port' => $clientInfo['port'],
			'heartbeat' => time()
		);
		$server->redis->set('client', json_encode($client));
	}
	if(!$message) {
		$server->sendto($clientInfo['address'], $clientInfo['port'], json_encode(Array(
			"status" => "error",
			"message" => "Invalid Message"
		)));
	} else {
		if(isset($message['type'])) {
			switch($message['type']) {
				case "message":
					if(isset($message['username']) && isset($message['message'])) {
						echo date("[H:i:s]") . "[{$message['username']}]<{$clientName}> {$message['message']}";
						foreach($client as $user) {
							$server->sendto($user['host'], $user['port'], json_encode(Array(
								'time' => time(),
								'type' => 'message',
								'username' => $message['username'],
								'message' => $message['message']
							)));
						}
					}
					break;
				case "heartbeat":
					$client[$clientName]['heartbeat'] = time();
					$server->redis->set('client', json_encode($client));
					break;
			}
		}
	}
});
$server->on('Start', function ($server) {
	while(true) {
		echo date("[H:i:s] ") . $server->redis->get('client') . "\n";
		$client = json_decode($server->redis->get('client'), true);
		foreach($client as $user) {
			$server->sendto($user['host'], $user['port'], json_encode(Array(
				'type' => 'heartbeat'
			)));
			if((time() - $user['heartbeat']) > 10) {
				echo date("[H:i:s] ") . "Client {$user['host']}:{$user['port']} timeout after 10 seconds\n";
				unset($client["{$user['host']}:{$user['port']}"]);
				$server->redis->set('client', json_encode($client));
			}
		}
		sleep(3);
	}
});
$server->start();
