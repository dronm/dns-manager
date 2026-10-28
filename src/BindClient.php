<?php

declare(strict_types=1);

namespace DnsManager;

use RuntimeException;

final class BindClient
{
	public function __construct(private readonly Config $config)
	{
	}

	public function validate(string $contents): void
	{
		$temporary = tempnam(sys_get_temp_dir(), 'dns-manager-check-');
		if ($temporary === false) {
			throw new RuntimeException('Cannot create a temporary validation file.');
		}
		try {
			if (file_put_contents($temporary, $contents) !== strlen($contents)) {
				throw new RuntimeException('Cannot write the validation file.');
			}
			$result = ProcessRunner::run([
				$this->config->binaries['named_checkzone'], '-q', '-k', $this->config->checkNames,
				$this->config->zone, $temporary,
			], '', $this->config->timeout);
			if ($result['exit_code'] !== 0) {
				throw new RuntimeException('named-checkzone rejected the candidate source: ' . self::details($result));
			}
		} finally {
			unlink($temporary);
		}
	}

	public function preflight(): void
	{
		foreach (['nsupdate', 'dig'] as $name) {
			ProcessRunner::executable($this->config->binaries[$name]);
		}
		if (!is_file($this->config->keyFile) || !is_readable($this->config->keyFile)) {
			throw new RuntimeException('Cannot read the TSIG key file: ' . $this->config->keyFile . '. Configure a dedicated update key before applying changes.');
		}
	}

	/** @param list<Record> $records */
	public function input(array $records, bool $enabled): string
	{
		$lines = [
			'server ' . $this->config->server . ' ' . $this->config->port,
			'zone ' . $this->config->zone . '.',
			'check-names no',
		];
		foreach ($records as $record) {
			$lines[] = $record->renderUpdate($enabled);
		}
		$lines[] = 'send';
		return implode("\n", $lines) . "\n";
	}

	/** @param list<Record> $records */
	public function apply(array $records, bool $enabled): void
	{
		$result = ProcessRunner::run([
			$this->config->binaries['nsupdate'], '-v', '-k', $this->config->keyFile,
			'-t', (string) $this->config->timeout,
		], $this->input($records, $enabled), $this->config->timeout);
		if ($result['exit_code'] !== 0) {
			throw new RuntimeException('nsupdate failed: ' . self::details($result));
		}
		$this->verify($records, $enabled);
	}

	/** @param list<Record> $records */
	private function verify(array $records, bool $enabled): void
	{
		$groups = [];
		foreach ($records as $record) {
			$groups[$record->owner . '|' . $record->type][] = $record;
		}
		foreach ($groups as $group) {
			$owner = $group[0]->owner;
			$type = $group[0]->type;
			$lastError = null;
			for ($attempt = 0; $attempt < 3; $attempt++) {
				if ($attempt > 0) {
					usleep(200000 * $attempt);
				}
				$actual = $this->query($owner, $type);
				$lastError = null;
				foreach ($group as $record) {
					$found = $actual[$record->identity()] ?? null;
					if ($enabled && $found === null) {
						$lastError = 'Expected record is absent: ' . $owner . ' ' . $type . ' (source line ' . $record->lineNumber . ')';
						break;
					}
					if (!$enabled && $found !== null) {
						$lastError = 'Expected record is still present: ' . $owner . ' ' . $type . ' (source line ' . $record->lineNumber . ')';
						break;
					}
					if ($enabled && $found->ttl !== $record->ttl) {
						$lastError = 'Record TTL differs from the source: ' . $owner . ' ' . $type . ' (expected ' . $record->ttl . ', received ' . $found->ttl . ')';
						break;
					}
				}
				if ($lastError === null) {
					break;
				}
			}
			if ($lastError !== null) {
				throw new RuntimeException('Authoritative verification failed. ' . $lastError . '.');
			}
		}
	}

	/** @return array<string, Record> */
	private function query(string $owner, string $type): array
	{
		$result = ProcessRunner::run([
			$this->config->binaries['dig'], '-r', '-k', $this->config->keyFile,
			'@' . $this->config->server, '-p', (string) $this->config->port, $owner, $type,
			'+tcp', '+norecurse', '+noall', '+answer', '+comments', '+nomultiline',
			'+time=' . $this->config->timeout, '+tries=1',
		], '', $this->config->timeout);
		if ($result['exit_code'] !== 0) {
			throw new RuntimeException('Authoritative verification query failed: ' . self::details($result));
		}
		$output = $result['stdout'];
		if (preg_match('/\bstatus:\s*(NOERROR|NXDOMAIN),/', $output) !== 1 || preg_match('/^;; flags:\s*[^;]*\baa\b[^;]*;/m', $output) !== 1) {
			throw new RuntimeException('Verification did not receive an authoritative NOERROR/NXDOMAIN response for ' . $owner . ' ' . $type . '. Check the primary address, TSIG key, view, and query permissions.');
		}
		$lines = preg_split('/\r?\n/', $output) ?: [];
		$diagnostics = $result['stderr'] . "\n" . implode("\n", array_filter($lines, static fn (string $line): bool => str_starts_with($line, ';;')));
		if (preg_match('/((?:TSIG|SIG\(0\)).*(?:fail|error|invalid)|Could(?: not|n.t) verify signature|Expected\s+(?:a\s+)?(?:TSIG|SIG\(0\)))/i', $diagnostics) === 1) {
			throw new RuntimeException('TSIG verification failed for the authoritative response.');
		}
		$records = [];
		foreach ($lines as $line) {
			if ($line === '' || str_starts_with($line, ';')) {
				continue;
			}
			if (preg_match('/^(\S+)\s+(\d+)\s+IN\s+(\S+)\s+(.+)$/D', $line, $matches) !== 1) {
				throw new RuntimeException('Could not parse an authoritative answer line.');
			}
			if (Record::normalizeName($matches[1], '.') !== $owner || strtoupper($matches[3]) !== $type) {
				continue;
			}
			$record = Record::fromText($matches[1], (int) $matches[2], $matches[3], $matches[4], $this->config->zone . '.', $this->config->zone);
			$records[$record->identity()] = $record;
		}
		return $records;
	}

	private static function details(array $result): string
	{
		$text = trim($result['stderr'] . "\n" . $result['stdout']);
		return $text !== '' ? substr($text, 0, 8192) : 'exit code ' . $result['exit_code'];
	}
}
