<?php

declare(strict_types=1);

require __DIR__ . '/TestSupport.php';

use DnsManager\Tests\Suite;
use function DnsManager\Tests\command;
use function DnsManager\Tests\expect;
use function DnsManager\Tests\fixture;
use function DnsManager\Tests\removeTree;
use function DnsManager\Tests\same;

/** This harness only starts and contacts its own 127.0.0.1 fixture. */
function executable(string $environment, string $fallback): string {
	$override = getenv($environment);
	if ($override !== false && $override !== '') {
		if (!is_executable($override)) {
			throw new RuntimeException($environment . ' is not executable: ' . $override);
		}
		return $override;
	}
	foreach (explode(PATH_SEPARATOR, (string) getenv('PATH')) as $directory) {
		$path = $directory . DIRECTORY_SEPARATOR . $fallback;
		if (is_executable($path) && is_file($path)) {
			return $path;
		}
	}
	throw new RuntimeException('Required integration-test executable not found: ' . $fallback);
}

function bindQuote(string $value): string {
	return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
}

$directory = sys_get_temp_dir() . '/dns-manager-test-' . bin2hex(random_bytes(8));
$server = null;
$suite = new Suite();
$status = 1;

try {
	$named = executable('DNS_MANAGER_NAMED_BINARY', 'named');
	$dig = executable('DNS_MANAGER_DIG_BINARY', 'dig');
	$nsupdate = executable('DNS_MANAGER_NSUPDATE_BINARY', 'nsupdate');
	$checkzone = executable('DNS_MANAGER_CHECKZONE_BINARY', 'named-checkzone');
	mkdir($directory, 0700);
	$reservation = stream_socket_server('tcp://127.0.0.1:0', $socketError, $socketMessage);
	if (!is_resource($reservation)) {
		throw new RuntimeException('Could not reserve a localhost test port: ' . $socketMessage);
	}
	$address = stream_socket_get_name($reservation, false);
	$port = (int) substr((string) $address, strrpos((string) $address, ':') + 1);
	fclose($reservation);

	$original = fixture();
	$source = $directory . '/source.zone';
	$liveZone = $directory . '/live.zone';
	$keyFile = $directory . '/test.key';
	$configFile = $directory . '/manager.json';
	$bindConfig = $directory . '/named.conf';
	file_put_contents($source, $original);
	file_put_contents($liveZone, $original);
	file_put_contents($keyFile, 'key "dns-manager-test" { algorithm hmac-sha256; secret "' . base64_encode(random_bytes(32)) . '"; };' . "\n");
	chmod($keyFile, 0600);
	$namedConfiguration = 'include ' . bindQuote($keyFile) . ";\n";
	$namedConfiguration .= 'options { directory ' . bindQuote($directory) . '; listen-on port ' . $port . ' { 127.0.0.1; }; listen-on-v6 { none; }; recursion no; dnssec-validation no; trust-anchor-telemetry no; empty-zones-enable no; pid-file ' . bindQuote($directory . '/named.pid') . '; session-keyfile ' . bindQuote($directory . '/session.key') . "; };\n";
	$namedConfiguration .= "controls { };\n";
	$namedConfiguration .= 'zone "example.test" { type primary; file ' . bindQuote($liveZone) . '; update-policy { grant dns-manager-test zonesub ANY; }; check-names warn; };' . "\n";
	file_put_contents($bindConfig, $namedConfiguration);
	$server = proc_open([$named, '-g', '-c', $bindConfig, '-n', '1', '-U', '1'], [0 => ['file', '/dev/null', 'r'], 1 => ['file', $directory . '/named.log', 'a'], 2 => ['file', $directory . '/named.log', 'a']], $serverPipes);
	if (!is_resource($server)) {
		throw new RuntimeException('Could not launch the isolated BIND fixture');
	}
	$query = static fn (string $owner, string $type): array => command([$dig, '@127.0.0.1', '-p', (string) $port, $owner, $type, '+tcp', '+norecurse', '+short', '+time=1', '+tries=1']);
	$ready = false;
	for ($attempt = 0; $attempt < 30; $attempt++) {
		$answer = $query('example.test.', 'SOA');
		if ($answer['code'] === 0 && str_contains($answer['stdout'], 'ns1.example.test.')) {
			$ready = true;
			break;
		}
		if (!proc_get_status($server)['running']) {
			break;
		}
		usleep(100000);
	}
	if (!$ready) {
		throw new RuntimeException('Isolated BIND did not start: ' . file_get_contents($directory . '/named.log'));
	}

	$config = [
		'binaries' => ['nsupdate' => $nsupdate, 'named_checkzone' => $checkzone, 'dig' => $dig],
		'timeout_sec' => 2,
		'lock_timeout_sec' => 1,
		'zones' => ['example.test' => ['source_file' => $source, 'server' => '127.0.0.1', 'port' => $port, 'key_file' => $keyFile, 'check_names' => 'warn']],
	];
	$saveConfig = static function () use (&$config, $configFile): void {
		file_put_contents($configFile, json_encode($config, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n");
	};
	$saveConfig();
	$run = static fn (array $arguments): array => command([PHP_BINARY, '-n', __DIR__ . '/../dns-manager', '--config', $configFile, '--zone', 'example.test', ...$arguments]);
	$assertSuccess = static function (array $result): void {
		same(0, $result['code'], 'CLI failed: ' . $result['stdout'] . $result['stderr']);
	};
	$update = static function (string $instructions) use ($nsupdate, $keyFile, $port): void {
		$result = command([$nsupdate, '-v', '-k', $keyFile, '-t', '2'], "server 127.0.0.1 {$port}\nzone example.test.\ncheck-names no\n" . $instructions . "\nsend\n");
		same(0, $result['code'], 'Fixture update failed: ' . $result['stderr']);
	};

	$suite->test('Dry run changes neither source nor authoritative data', static function () use ($run, $assertSuccess, $source, $original, $query): void {
		$assertSuccess($run(['meln', 'disable', '--dry-run']));
		same($original, file_get_contents($source), 'Dry run modified the source');
		expect(str_contains($query('www.example.test.', 'A')['stdout'], '192.0.2.20'), 'Dry run modified DNS');
	});

	$suite->test('Disable changes exact tagged values and preserves shared infrastructure and TXT', static function () use ($run, $assertSuccess, $source, $query): void {
		$assertSuccess($run(['meln', 'disable']));
		same(6, substr_count((string) file_get_contents($source), ';! '), 'Wrong disabled marker count');
		same("192.0.2.10\n", $query('www.example.test.', 'A')['stdout'], 'Other backend not preserved');
		same("192.0.2.20\n", $query('ns3.example.test.', 'A')['stdout'], 'Infrastructure address was removed');
		same("\"permanent\"\n", $query('txt.example.test.', 'TXT')['stdout'], 'Unrelated TXT value was removed');
		same('', $query('_service._tcp.example.test.', 'SRV')['stdout'], 'Tagged SRV was not removed');
		same('', $query('example.test.', 'MX')['stdout'], 'Tagged MX was not removed');
	});

	$suite->test('Enable restores all record types and original source bytes', static function () use ($run, $assertSuccess, $source, $original, $query): void {
		$assertSuccess($run(['enable', 'meln']));
		same($original, file_get_contents($source), 'Restoration lost source formatting');
		expect(str_contains($query('www.example.test.', 'A')['stdout'], '192.0.2.20'), 'Address not restored');
		expect(str_contains($query('txt.example.test.', 'TXT')['stdout'], 'quoted; dm=not-a-tag'), 'Quoted TXT not restored');
		expect(str_contains($query('_service._tcp.example.test.', 'SRV')['stdout'], '10 5 443 api.example.test.'), 'Relative SRV target not restored');
		expect(str_contains($query('example.test.', 'MX')['stdout'], '10 mail.example.test.'), 'Relative MX target not restored');
		expect(str_contains($query('odd_name.example.test.', 'A')['stdout'], '192.0.2.20'), 'Permitted underscore owner was skipped');
	});

	$suite->test('Repeated enable repairs DNS even when source is already enabled', static function () use ($update, $run, $assertSuccess, $query): void {
		$update('update delete www.example.test. IN A 192.0.2.20');
		$assertSuccess($run(['meln', 'enable']));
		expect(str_contains($query('www.example.test.', 'A')['stdout'], '192.0.2.20'), 'Repeated enable was a false no-op');
	});

	$suite->test('Other supported RR types round-trip through real BIND presentation formats', static function () use ($run, $assertSuccess, $query, $source, $original): void {
		$owners = ['v6' => 'AAAA', 'semi\\;colon' => 'A', 'canonical' => 'CNAME', 'ptr' => 'PTR', 'dname' => 'DNAME', 'caa' => 'CAA', 'sshfp' => 'SSHFP', '_443._tcp.tlsa' => 'TLSA'];
		$assertSuccess($run(['other', 'disable']));
		foreach ($owners as $owner => $type) {
			same('', $query($owner . '.example.test.', $type)['stdout'], $type . ' was not removed');
		}
		$assertSuccess($run(['other', 'enable']));
		foreach ($owners as $owner => $type) {
			expect($query($owner . '.example.test.', $type)['stdout'] !== '', $type . ' was not restored');
		}
		same($original, file_get_contents($source), 'Mixed-type round-trip changed source bytes');
	});

	$suite->test('Repeated disable repairs DNS even when source is already disabled', static function () use ($update, $run, $assertSuccess, $query): void {
		$assertSuccess($run(['meln', 'disable']));
		$update('update add www.example.test. 60 IN A 192.0.2.20');
		$assertSuccess($run(['meln', 'disable']));
		same("192.0.2.10\n", $query('www.example.test.', 'A')['stdout'], 'Repeated disable was a false no-op');
		$assertSuccess($run(['meln', 'enable']));
	});

	$suite->test('Unknown alias fails before source or DNS changes', static function () use ($run, $source, $query): void {
		$before = file_get_contents($source);
		$result = $run(['mel', 'disable']);
		expect($result['code'] !== 0, 'Unknown alias returned success');
		same($before, file_get_contents($source), 'Unknown alias changed source');
		expect(str_contains($query('www.example.test.', 'A')['stdout'], '192.0.2.20'), 'Unknown alias changed DNS');
	});

	$suite->test('Concurrent writer lock prevents source and DNS changes', static function () use ($run, $source, $query): void {
		$before = file_get_contents($source);
		$lock = fopen($source . '.lock', 'c');
		if (!is_resource($lock) || !flock($lock, LOCK_EX | LOCK_NB)) {
			throw new RuntimeException('Could not obtain test writer lock');
		}
		try {
			$result = $run(['meln', 'disable']);
			expect($result['code'] !== 0, 'Concurrent operation did not respect the lock');
			same($before, file_get_contents($source), 'Locked source was modified');
			expect(str_contains($query('www.example.test.', 'A')['stdout'], '192.0.2.20'), 'Locked operation modified DNS');
		} finally {
			flock($lock, LOCK_UN);
			fclose($lock);
		}
	});

	$suite->test('Missing authentication key fails before saving desired state', static function () use (&$config, $saveConfig, $run, $source, $keyFile): void {
		$before = file_get_contents($source);
		$config['zones']['example.test']['key_file'] = $keyFile . '.missing';
		$saveConfig();
		try {
			$readOnly = $run(['status']);
			same(0, $readOnly['code'], 'Status unnecessarily required authentication: ' . $readOnly['stderr']);
			$result = $run(['meln', 'disable']);
			expect($result['code'] !== 0, 'Missing key returned success');
			same($before, file_get_contents($source), 'Missing key changed source');
		} finally {
			$config['zones']['example.test']['key_file'] = $keyFile;
			$saveConfig();
		}
	});

	$suite->test('Rejected update leaves desired state saved and retryable', static function () use (&$config, $saveConfig, $run, $assertSuccess, $source, $directory, $nsupdate, $query): void {
		$failure = $directory . '/reject-update';
		file_put_contents($failure, "#!/bin/sh\nexit 17\n");
		chmod($failure, 0700);
		$config['binaries']['nsupdate'] = $failure;
		$saveConfig();
		try {
			$result = $run(['meln', 'disable']);
			expect($result['code'] !== 0, 'Rejected update returned success');
			same(6, substr_count((string) file_get_contents($source), ';! '), 'Desired disable was not saved');
			expect(str_contains($query('www.example.test.', 'A')['stdout'], '192.0.2.20'), 'Failure fixture unexpectedly changed DNS');
		} finally {
			$config['binaries']['nsupdate'] = $nsupdate;
			$saveConfig();
		}
		$assertSuccess($run(['meln', 'disable']));
		same("192.0.2.10\n", $query('www.example.test.', 'A')['stdout'], 'Retry did not apply pending disable');
		$assertSuccess($run(['meln', 'enable']));
	});

	$suite->test('Hung updater is bounded by the configured timeout', static function () use (&$config, $saveConfig, $run, $assertSuccess, $source, $directory, $nsupdate): void {
		$hung = $directory . '/hung-update';
		file_put_contents($hung, "#!/bin/sh\nexec /usr/bin/sleep 30\n");
		chmod($hung, 0700);
		$config['binaries']['nsupdate'] = $hung;
		$saveConfig();
		try {
			$result = $run(['meln', 'disable']);
			expect($result['code'] !== 0, 'Timed-out update returned success');
			expect($result['elapsed'] < 8.0, 'Timeout did not bound the updater');
			same(6, substr_count((string) file_get_contents($source), ';! '), 'Desired state missing after timeout');
		} finally {
			$config['binaries']['nsupdate'] = $nsupdate;
			$saveConfig();
		}
		$assertSuccess($run(['meln', 'enable']));
	});

	$suite->test('Authoritative verification catches an update silently skipped by BIND', static function () use ($run, $assertSuccess, $update, $query): void {
		$assertSuccess($run(['meln', 'disable']));
		$update('update add api.example.test. 60 IN CNAME www.example.test.');
		try {
			$result = $run(['meln', 'enable']);
			expect($result['code'] !== 0, 'Missing desired A record was reported as applied');
			expect(str_contains($query('api.example.test.', 'CNAME')['stdout'], 'www.example.test.'), 'Conflict fixture did not exist');
		} finally {
			$update('update delete api.example.test. IN CNAME www.example.test.');
		}
		$assertSuccess($run(['meln', 'enable']));
	});

	$suite->test('Authoritative-looking reply with failed TSIG authentication is rejected', static function () use (&$config, $saveConfig, $run, $assertSuccess, $directory, $dig): void {
		$fakeDig = $directory . '/unsigned-answer';
		file_put_contents($fakeDig, <<<'SCRIPT'
#!/bin/sh
cat <<'ANSWER'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
www.example.test. 60 IN A 192.0.2.10
;; Couldn't verify signature: expected a TSIG or SIG(0)
ANSWER
SCRIPT
		);
		chmod($fakeDig, 0700);
		$config['binaries']['dig'] = $fakeDig;
		$saveConfig();
		try {
			$result = $run(['meln', 'disable']);
			same(4, $result['code'], 'Unauthenticated reply was reported as verified: ' . $result['stdout'] . $result['stderr']);
			expect(str_contains($result['stderr'], 'TSIG'), 'Authentication failure was not identified');
		} finally {
			$config['binaries']['dig'] = $dig;
			$saveConfig();
		}
		$assertSuccess($run(['meln', 'enable']));
	});

	$suite->test('Invalid candidate is rejected before source replacement', static function () use ($source, $original, $run, $query): void {
		$invalid = $original . "www 60 IN CNAME alias.example.test. ; dm=conflict\n";
		file_put_contents($source, $invalid);
		try {
			$result = $run(['conflict', 'enable']);
			expect($result['code'] !== 0, 'Invalid CNAME coexistence was accepted');
			same($invalid, file_get_contents($source), 'Invalid candidate changed source');
			expect(str_contains($query('www.example.test.', 'A')['stdout'], '192.0.2.20'), 'Invalid candidate changed DNS');
		} finally {
			file_put_contents($source, $original);
		}
	});

	$status = $suite->finish();
} catch (Throwable $error) {
	fwrite(STDERR, 'Integration setup failed: ' . $error->getMessage() . "\n");
} finally {
	if (is_resource($server)) {
		proc_terminate($server);
		$deadline = microtime(true) + 3.0;
		while (proc_get_status($server)['running'] && microtime(true) < $deadline) {
			usleep(10000);
		}
		if (proc_get_status($server)['running']) {
			proc_terminate($server, 9);
		}
		proc_close($server);
	}
	if (is_dir($directory)) {
		removeTree($directory);
	}
}

exit($status);
