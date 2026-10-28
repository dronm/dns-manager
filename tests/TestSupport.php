<?php

declare(strict_types=1);

namespace DnsManager\Tests;

use RuntimeException;
use Throwable;

final class Suite {
	private int $passed = 0;
	private int $failed = 0;

	public function test(string $name, callable $test): void {
		try {
			$test();
			$this->passed++;
			fwrite(STDOUT, "PASS {$name}\n");
		} catch (Throwable $error) {
			$this->failed++;
			fwrite(STDERR, "FAIL {$name}: {$error->getMessage()}\n");
		}
	}

	public function finish(): int {
		fwrite(STDOUT, "\n{$this->passed} passed; {$this->failed} failed.\n");
		return $this->failed === 0 ? 0 : 1;
	}
}

function expect(bool $condition, string $message): void {
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

function same(mixed $expected, mixed $actual, string $message): void {
	if ($expected !== $actual) {
		throw new RuntimeException($message . '; expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
	}
}

function throws(callable $operation, string $message): void {
	try {
		$operation();
	} catch (Throwable) {
		return;
	}
	throw new RuntimeException($message);
}

function fixture(): string {
	return <<<'ZONE'
$ORIGIN example.test.
$TTL 3600

; This ordinary comment must survive every operation.
@ 3600 IN SOA ns1.example.test. hostmaster.example.test. (
	2026102801
	3600
	600
	604800
	300
)
@ 3600 IN NS ns1.example.test.
ns1 3600 IN A 127.0.0.1
ns3 3600 IN A 192.0.2.20 ; infrastructure sharing the application address
mail 3600 IN A 192.0.2.30
www 60 IN A 192.0.2.10 ; dm=sakko
www 60 IN A 192.0.2.20 ; dm=meln
api 60 IN A 192.0.2.20 ; dm=meln
odd_name 60 IN A 192.0.2.20 ; dm=meln
txt 60 IN TXT "permanent"
txt 60 IN TXT "quoted; dm=not-a-tag" "second string" ; dm=meln
_service._tcp 60 IN SRV 10 5 443 api ; dm=meln
@ 60 IN MX 10 mail ; dm=meln
alias 60 IN CNAME www
v6 60 IN AAAA 2001:db8::20 ; dm=other
semi\;colon 60 IN A 192.0.2.40 ; dm=other
canonical 60 IN CNAME www ; dm=other
ptr 60 IN PTR mail ; dm=other
dname 60 IN DNAME target.example.net. ; dm=other
caa 60 IN CAA 0 IsSuE "letsencrypt.org" ; dm=other
sshfp 60 IN SSHFP 1 1 1234567890123456789012345678901234567890 ; dm=other
_443._tcp.tlsa 60 IN TLSA 3 1 1 1234567890123456789012345678901234567890123456789012345678901234 ; dm=other

ZONE;
}

/** @return array{code:int,stdout:string,stderr:string,elapsed:float} */
function command(array $arguments, string $input = '', float $timeout = 15.0): array {
	$stdout = tmpfile();
	$stderr = tmpfile();
	if ($stdout === false || $stderr === false) {
		throw new RuntimeException('Could not create process output streams');
	}
	$started = microtime(true);
	$process = proc_open($arguments, [0 => ['pipe', 'r'], 1 => $stdout, 2 => $stderr], $pipes);
	if (!is_resource($process)) {
		throw new RuntimeException('Could not start process');
	}
	if ($input !== '') {
		fwrite($pipes[0], $input);
	}
	fclose($pipes[0]);
	$exitCode = -1;
	while (true) {
		$status = proc_get_status($process);
		if (!$status['running']) {
			$exitCode = $status['exitcode'];
			break;
		}
		if (microtime(true) - $started > $timeout) {
			proc_terminate($process, 9);
			proc_close($process);
			fclose($stdout);
			fclose($stderr);
			throw new RuntimeException('Test subprocess exceeded ' . $timeout . ' seconds');
		}
		usleep(10000);
	}
	$closedCode = proc_close($process);
	if ($exitCode < 0) {
		$exitCode = $closedCode;
	}
	rewind($stdout);
	rewind($stderr);
	$out = stream_get_contents($stdout);
	$err = stream_get_contents($stderr);
	fclose($stdout);
	fclose($stderr);
	return ['code' => $exitCode, 'stdout' => (string) $out, 'stderr' => (string) $err, 'elapsed' => microtime(true) - $started];
}

function removeTree(string $directory): void {
	if (!is_dir($directory) || is_link($directory)) {
		return;
	}
	foreach (new \FilesystemIterator($directory) as $entry) {
		if ($entry->isDir() && !$entry->isLink()) {
			removeTree($entry->getPathname());
		} else {
			unlink($entry->getPathname());
		}
	}
	rmdir($directory);
}
