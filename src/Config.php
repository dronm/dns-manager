<?php

declare(strict_types=1);

namespace DnsManager;

use InvalidArgumentException;
use JsonException;

final class Config
{
	public readonly string $zone;
	public readonly string $sourceFile;
	public readonly string $server;
	public readonly int $port;
	public readonly string $keyFile;
	public readonly string $checkNames;
	public readonly int $timeout;
	public readonly int $lockTimeout;
	/** @var array<string, string> */
	public readonly array $binaries;

	public function __construct(string $path, ?string $requestedZone)
	{
		$realPath = realpath($path);
		if ($realPath === false || !is_file($realPath) || !is_readable($realPath)) {
			throw new InvalidArgumentException('Cannot read configuration: ' . $path);
		}
		$text = file_get_contents($realPath);
		if ($text === false) {
			throw new InvalidArgumentException('Cannot read configuration: ' . $path);
		}
		try {
			$data = json_decode($text, true, 64, JSON_THROW_ON_ERROR);
		} catch (JsonException $error) {
			throw new InvalidArgumentException('Invalid configuration JSON: ' . $error->getMessage());
		}
		if (!is_array($data) || !isset($data['zones']) || !is_array($data['zones']) || $data['zones'] === []) {
			throw new InvalidArgumentException('Configuration must contain a nonempty zones object.');
		}
		self::knownKeys($data, ['binaries', 'timeout_sec', 'lock_timeout_sec', 'zones'], 'configuration');
		$zones = [];
		foreach ($data['zones'] as $name => $settings) {
			if (!is_string($name)) {
				throw new InvalidArgumentException('Zone names must be strings.');
			}
			$normalized = self::zoneName($name);
			if (isset($zones[$normalized])) {
				throw new InvalidArgumentException('Duplicate normalized zone name: ' . $normalized);
			}
			$zones[$normalized] = $settings;
		}
		if ($requestedZone === null) {
			if (count($zones) !== 1) {
				throw new InvalidArgumentException('Use --zone when more than one zone is configured.');
			}
			$requestedZone = (string) array_key_first($zones);
		}
		$this->zone = self::zoneName($requestedZone);
		if (!isset($zones[$this->zone]) || !is_array($zones[$this->zone])) {
			throw new InvalidArgumentException('Zone is not configured: ' . $this->zone);
		}
		$zone = $zones[$this->zone];
		self::knownKeys($zone, ['source_file', 'server', 'port', 'key_file', 'check_names'], 'zone ' . $this->zone);
		$directory = dirname($realPath);
		$this->sourceFile = self::absolutePath(self::stringValue($zone, 'source_file'), $directory);
		$this->keyFile = self::absolutePath(self::stringValue($zone, 'key_file'), $directory);
		$this->server = self::stringValue($zone, 'server');
		if (filter_var($this->server, FILTER_VALIDATE_IP) === false && preg_match('/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.?$/D', $this->server) !== 1) {
			throw new InvalidArgumentException('server must be an IP address or a DNS hostname without whitespace.');
		}
		$this->port = self::integer($zone['port'] ?? 53, 1, 65535, 'port');
		$this->timeout = self::integer($data['timeout_sec'] ?? 15, 1, 300, 'timeout_sec');
		$this->lockTimeout = self::integer($data['lock_timeout_sec'] ?? 5, 0, 60, 'lock_timeout_sec');
		$this->checkNames = $zone['check_names'] ?? 'warn';
		if (!in_array($this->checkNames, ['fail', 'warn', 'ignore'], true)) {
			throw new InvalidArgumentException('check_names must be fail, warn, or ignore.');
		}
		$binaries = $data['binaries'] ?? [];
		if (!is_array($binaries)) {
			throw new InvalidArgumentException('binaries must be an object.');
		}
		self::knownKeys($binaries, ['nsupdate', 'named_checkzone', 'dig'], 'binaries');
		$resolved = [];
		foreach (['nsupdate' => 'nsupdate', 'named_checkzone' => 'named-checkzone', 'dig' => 'dig'] as $name => $default) {
			$value = $binaries[$name] ?? $default;
			if (!is_string($value) || $value === '' || preg_match('/[\x00-\x1f\x7f]/', $value) === 1) {
				throw new InvalidArgumentException('Invalid executable setting: ' . $name);
			}
			$resolved[$name] = str_contains($value, '/') ? self::absolutePath($value, $directory) : $value;
		}
		$this->binaries = $resolved;
	}

	public static function zoneName(string $value): string
	{
		$value = strtolower(rtrim($value, '.'));
		if ($value === '' || strlen($value) > 253) {
			throw new InvalidArgumentException('Invalid zone name.');
		}
		foreach (explode('.', $value) as $label) {
			if (preg_match('/^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/D', $label) !== 1) {
				throw new InvalidArgumentException('Invalid zone name: ' . $value);
			}
		}
		return $value;
	}

	private static function stringValue(array $values, string $key): string
	{
		$value = $values[$key] ?? null;
		if (!is_string($value) || $value === '' || preg_match('/[\x00-\x1f\x7f]/', $value) === 1) {
			throw new InvalidArgumentException('Missing or invalid configuration value: ' . $key);
		}
		return $value;
	}

	private static function absolutePath(string $path, string $directory): string
	{
		return str_starts_with($path, '/') ? $path : $directory . '/' . $path;
	}

	private static function integer(mixed $value, int $minimum, int $maximum, string $name): int
	{
		if (!is_int($value) || $value < $minimum || $value > $maximum) {
			throw new InvalidArgumentException($name . ' must be an integer from ' . $minimum . ' to ' . $maximum . '.');
		}
		return $value;
	}

	private static function knownKeys(array $values, array $allowed, string $section): void
	{
		foreach (array_keys($values) as $key) {
			if (!in_array($key, $allowed, true)) {
				throw new InvalidArgumentException('Unknown ' . $section . ' field: ' . $key);
			}
		}
	}
}
