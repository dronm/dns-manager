<?php

declare(strict_types=1);

namespace DnsManager;

use InvalidArgumentException;

/**
 * One fully qualified IN record. Source formatting stays in ZoneSource.
 */
final class Record {
	public const SUPPORTED_TYPES = [
		'A', 'AAAA', 'CNAME', 'PTR', 'DNAME', 'MX', 'SRV',
		'TXT', 'CAA', 'SSHFP', 'TLSA',
	];

	private function __construct(
		public readonly string $owner,
		public readonly int $ttl,
		public readonly string $type,
		public readonly string $rdata,
		public readonly string $alias,
		public readonly int $lineNumber,
		public readonly bool $enabled,
	) {
	}

	public static function fromText(
		string $owner,
		int $ttl,
		string $type,
		string $rdata,
		string $origin,
		string $zone,
		string $alias = '',
		int $lineNumber = 0,
		bool $enabled = true,
	): self {
		try {
			$zone = self::normalizeName($zone, '.');
			$origin = self::normalizeName($origin, $zone);
			$owner = self::normalizeName($owner, $origin);
			$type = strtoupper($type);

			if ($ttl < 0 || $ttl > 2147483647) {
				throw new InvalidArgumentException('TTL must be between 0 and 2147483647.');
			}

			if (!self::isWithinZone($owner, $zone)) {
				throw new InvalidArgumentException('Record owner is outside the configured zone: ' . $owner);
			}

			if ($alias !== '' && !preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z/D', $alias)) {
				throw new InvalidArgumentException('Invalid server alias: ' . $alias);
			}

			if (!in_array($type, self::SUPPORTED_TYPES, true)) {
				throw new InvalidArgumentException('Unsupported managed record type: ' . $type);
			}

			[$data, , $hasComment] = self::splitComment($rdata);

			if ($hasComment) {
				throw new InvalidArgumentException('Record data contains an unescaped comment delimiter.');
			}

			$tokens = self::lex($data);
			$normalized = self::normalizeRdata($type, $tokens, $origin);

			if (in_array($type, ['CNAME', 'DNAME'], true) && $normalized === $owner) {
				throw new InvalidArgumentException($type . ' must not point to its own owner.');
			}

			return new self($owner, $ttl, $type, $normalized, $alias, $lineNumber, $enabled);
		} catch (InvalidArgumentException $error) {
			if ($lineNumber > 0) {
				throw new InvalidArgumentException('Line ' . $lineNumber . ': ' . $error->getMessage(), 0, $error);
			}

			throw $error;
		}
	}

	/**
	 * TTL is an RRset property and is deliberately excluded from record identity.
	 */
	public function identity(): string {
		return $this->owner . "\tIN\t" . $this->type . "\t" . $this->rdata;
	}

	public function renderUpdate(bool $enabled): string {
		if ($enabled) {
			return sprintf(
				'update add %s %d IN %s %s',
				$this->owner,
				$this->ttl,
				$this->type,
				$this->rdata,
			);
		}

		return sprintf('update delete %s IN %s %s', $this->owner, $this->type, $this->rdata);
	}

	/**
	 * Split only on a real comment delimiter, never a quoted/escaped semicolon.
	 *
	 * @return array{string, string, bool}
	 */
	public static function splitComment(string $line): array {
		if (strpbrk($line, "\r\n\0") !== false) {
			throw new InvalidArgumentException('A record must occupy one physical line.');
		}

		$quoted = false;
		$length = strlen($line);

		for ($index = 0; $index < $length; $index++) {
			$character = $line[$index];

			if ($character === '\\') {
				if ($index + 1 >= $length) {
					throw new InvalidArgumentException('Trailing backslash in record data.');
				}

				$index++;
				continue;
			}

			if ($character === '"') {
				$quoted = !$quoted;
				continue;
			}

			if ($character === ';' && !$quoted) {
				return [substr($line, 0, $index), substr($line, $index + 1), true];
			}
		}

		if ($quoted) {
			throw new InvalidArgumentException('Unterminated quoted string.');
		}

		return [$line, '', false];
	}

	/**
	 * DNS tokens with their source spans. Backslashes are decoded in value while
	 * raw remains available for domain names whose escaped dots are significant.
	 *
	 * @return array<int, array{raw:string,value:string,quoted:bool,start:int,end:int}>
	 */
	public static function lex(string $text): array {
		$tokens = [];
		$length = strlen($text);
		$index = 0;

		while ($index < $length) {
			while ($index < $length && ($text[$index] === ' ' || $text[$index] === "\t")) {
				$index++;
			}

			if ($index === $length) {
				break;
			}

			$start = $index;
			$quoted = $text[$index] === '"';
			$value = '';

			if ($quoted) {
				$index++;
				$closed = false;

				while ($index < $length) {
					$character = $text[$index];

					if ($character === '"') {
						$index++;
						$closed = true;
						break;
					}

					if ($character === '\\') {
						$value .= self::decodeEscape($text, $index);
						continue;
					}

					self::assertPrintableInput($character);
					$value .= $character;
					$index++;
				}

				if (!$closed) {
					throw new InvalidArgumentException('Unterminated quoted string.');
				}

				if ($index < $length && $text[$index] !== ' ' && $text[$index] !== "\t") {
					throw new InvalidArgumentException('Quoted strings must be separated by whitespace.');
				}
			} else {
				while ($index < $length && $text[$index] !== ' ' && $text[$index] !== "\t") {
					$character = $text[$index];

					if ($character === '\\') {
						$value .= self::decodeEscape($text, $index);
						continue;
					}

					if (str_contains('";()', $character)) {
						throw new InvalidArgumentException('Unexpected quote, comment, or parenthesis in a managed record.');
					}

					self::assertPrintableInput($character);
					$value .= $character;
					$index++;
				}
			}

			$tokens[] = [
				'raw' => substr($text, $start, $index - $start),
				'value' => $value,
				'quoted' => $quoted,
				'start' => $start,
				'end' => $index,
			];
		}

		return $tokens;
	}

	/**
	 * Canonical absolute name, preserving label boundaries and escaped bytes.
	 */
	public static function normalizeName(string $name, string $origin): string {
		if ($name === '@') {
			if ($origin === '@') {
				throw new InvalidArgumentException('Invalid origin.');
			}

			return self::normalizeName($origin, '.');
		}

		[$labels, $absolute] = self::nameLabels($name);

		if (!$absolute) {
			[$originLabels, $originAbsolute] = self::nameLabels($origin);

			if (!$originAbsolute) {
				throw new InvalidArgumentException('Origin must be an absolute DNS name.');
			}

			$labels = [...$labels, ...$originLabels];
		}

		$wireLength = 1;
		$output = [];

		foreach ($labels as $label) {
			$wireLength += 1 + strlen($label);
			$rendered = '';

			for ($index = 0; $index < strlen($label); $index++) {
				$byte = ord($label[$index]);

				if ($byte >= 65 && $byte <= 90) {
					$byte += 32;
				}

				$character = chr($byte);

				if (($byte >= 97 && $byte <= 122) || ($byte >= 48 && $byte <= 57)
					|| in_array($character, ['-', '_', '*'], true)) {
					$rendered .= $character;
				} else {
					$rendered .= sprintf('\\%03d', $byte);
				}
			}

			$output[] = $rendered;
		}

		if ($wireLength > 255) {
			throw new InvalidArgumentException('DNS name exceeds 255 wire-format bytes.');
		}

		return $output === [] ? '.' : implode('.', $output) . '.';
	}

	public static function isWithinZone(string $owner, string $zone): bool {
		return $zone === '.' || $owner === $zone || str_ends_with($owner, '.' . $zone);
	}

	private static function normalizeRdata(string $type, array $tokens, string $origin): string {
		switch ($type) {
			case 'A':
				self::expectCount($tokens, 1);
				$address = self::plain($tokens[0]);

				if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
					throw new InvalidArgumentException('Invalid IPv4 address.');
				}

				return $address;

			case 'AAAA':
				self::expectCount($tokens, 1);
				$address = self::plain($tokens[0]);

				if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
					throw new InvalidArgumentException('Invalid IPv6 address.');
				}

				return (string) inet_ntop((string) inet_pton($address));

			case 'CNAME':
			case 'PTR':
			case 'DNAME':
				self::expectCount($tokens, 1);
				return self::normalizeName(self::plain($tokens[0]), $origin);

			case 'MX':
				self::expectCount($tokens, 2);
				return self::number($tokens[0], 65535) . ' '
					. self::normalizeName(self::plain($tokens[1]), $origin);

			case 'SRV':
				self::expectCount($tokens, 4);
				return implode(' ', [
					self::number($tokens[0], 65535),
					self::number($tokens[1], 65535),
					self::number($tokens[2], 65535),
					self::normalizeName(self::plain($tokens[3]), $origin),
				]);

			case 'TXT':
				if ($tokens === []) {
					throw new InvalidArgumentException('TXT requires at least one string.');
				}

				$total = 0;
				$strings = [];

				foreach ($tokens as $token) {
					if (strlen($token['value']) > 255) {
						throw new InvalidArgumentException('Each TXT string must be at most 255 bytes.');
					}

					$total += strlen($token['value']) + 1;
					$strings[] = self::quote($token['value']);
				}

				if ($total > 65535) {
					throw new InvalidArgumentException('TXT record data exceeds 65535 bytes.');
				}

				return implode(' ', $strings);

			case 'CAA':
				self::expectCount($tokens, 3);
				$flags = self::number($tokens[0], 255);
				$tag = $tokens[1]['value'];

				if (!preg_match('/\A[A-Za-z0-9]{1,255}\z/D', $tag)) {
					throw new InvalidArgumentException('CAA tag must contain 1 to 255 letters or digits.');
				}

				if (strlen($tokens[2]['value']) + strlen($tag) + 2 > 65535) {
					throw new InvalidArgumentException('CAA record data exceeds 65535 bytes.');
				}

				return $flags . ' ' . $tag . ' ' . self::quote($tokens[2]['value']);

			case 'SSHFP':
				if (count($tokens) < 3) {
					throw new InvalidArgumentException('SSHFP requires algorithm, fingerprint type, and fingerprint.');
				}

				$algorithm = self::number($tokens[0], 255);
				$fingerprintType = self::number($tokens[1], 255);
				$hex = self::hex(array_slice($tokens, 2));

				if (($fingerprintType === '1' && strlen($hex) !== 40)
					|| ($fingerprintType === '2' && strlen($hex) !== 64)) {
					throw new InvalidArgumentException('SSHFP fingerprint length does not match its type.');
				}

				return $algorithm . ' ' . $fingerprintType . ' ' . $hex;

			case 'TLSA':
				if (count($tokens) < 4) {
					throw new InvalidArgumentException('TLSA requires usage, selector, matching type, and association data.');
				}

				$usage = self::number($tokens[0], 255);
				$selector = self::number($tokens[1], 255);
				$matchingType = self::number($tokens[2], 255);
				$hex = self::hex(array_slice($tokens, 3));

				if (($matchingType === '1' && strlen($hex) !== 64)
					|| ($matchingType === '2' && strlen($hex) !== 128)) {
					throw new InvalidArgumentException('TLSA association length does not match its matching type.');
				}

				return $usage . ' ' . $selector . ' ' . $matchingType . ' ' . $hex;
		}

		throw new InvalidArgumentException('Unsupported record type: ' . $type);
	}

	private static function expectCount(array $tokens, int $expected): void {
		if (count($tokens) !== $expected) {
			throw new InvalidArgumentException('Expected ' . $expected . ' record-data field(s), got ' . count($tokens) . '.');
		}
	}

	private static function plain(array $token): string {
		if ($token['quoted']) {
			throw new InvalidArgumentException('This record-data field must not be quoted.');
		}

		return $token['raw'];
	}

	private static function number(array $token, int $maximum): string {
		$value = self::plain($token);

		if (!preg_match('/\A[0-9]+\z/D', $value)) {
			throw new InvalidArgumentException('Expected an unsigned decimal integer.');
		}

		$normalized = ltrim($value, '0');
		$normalized = $normalized === '' ? '0' : $normalized;
		$limit = (string) $maximum;

		if (strlen($normalized) > strlen($limit)
			|| (strlen($normalized) === strlen($limit) && strcmp($normalized, $limit) > 0)) {
			throw new InvalidArgumentException('Integer exceeds ' . $maximum . '.');
		}

		return $normalized;
	}

	private static function hex(array $tokens): string {
		$hex = '';

		foreach ($tokens as $token) {
			$hex .= self::plain($token);
		}

		if ($hex === '' || !preg_match('/\A[0-9a-fA-F]+\z/D', $hex) || strlen($hex) % 2 !== 0) {
			throw new InvalidArgumentException('Expected a nonempty, even-length hexadecimal value.');
		}

		if (strlen($hex) > 131000) {
			throw new InvalidArgumentException('Hexadecimal record data is too long.');
		}

		return strtoupper($hex);
	}

	private static function quote(string $value): string {
		$output = '"';

		for ($index = 0; $index < strlen($value); $index++) {
			$byte = ord($value[$index]);

			if ($byte < 32 || $byte > 126) {
				$output .= sprintf('\\%03d', $byte);
			} elseif ($value[$index] === '"' || $value[$index] === '\\') {
				$output .= '\\' . $value[$index];
			} else {
				$output .= $value[$index];
			}
		}

		return $output . '"';
	}

	private static function decodeEscape(string $text, int &$index): string {
		$length = strlen($text);
		$index++;

		if ($index >= $length) {
			throw new InvalidArgumentException('Trailing backslash.');
		}

		if ($text[$index] >= '0' && $text[$index] <= '9') {
			$digits = substr($text, $index, 3);

			if (strlen($digits) !== 3 || preg_match('/\A[0-9]{3}\z/D', $digits) !== 1 || (int) $digits > 255) {
				throw new InvalidArgumentException('A decimal DNS escape must contain three digits between 000 and 255.');
			}

			$index += 3;
			return chr((int) $digits);
		}

		self::assertPrintableInput($text[$index]);
		return $text[$index++];
	}

	private static function assertPrintableInput(string $character): void {
		if (ord($character) < 32 || ord($character) === 127) {
			throw new InvalidArgumentException('Raw control characters are not permitted in a record; use DNS escapes.');
		}
	}

	/** @return array{array<int,string>,bool} */
	private static function nameLabels(string $name): array {
		if ($name === '.') {
			return [[], true];
		}

		if ($name === '') {
			throw new InvalidArgumentException('DNS name must not be empty.');
		}

		$labels = [];
		$current = '';
		$length = strlen($name);
		$absolute = false;
		$index = 0;

		while ($index < $length) {
			$character = $name[$index];

			if ($character === '\\') {
				$current .= self::decodeEscape($name, $index);
				continue;
			}

			if ($character === '.') {
				if ($current === '') {
					throw new InvalidArgumentException('DNS name contains an empty label.');
				}

				$labels[] = $current;
				$current = '';
				$index++;
				$absolute = $index === $length;
				continue;
			}

			$byte = ord($character);

			if ($byte < 33 || $byte > 126 || str_contains('";()', $character)) {
				throw new InvalidArgumentException('DNS names must use ASCII labels or explicit DNS escapes.');
			}

			$current .= $character;
			$index++;
		}

		if (!$absolute) {
			if ($current === '') {
				throw new InvalidArgumentException('DNS name contains an empty label.');
			}

			$labels[] = $current;
		}

		foreach ($labels as $label) {
			if (strlen($label) > 63) {
				throw new InvalidArgumentException('DNS label exceeds 63 bytes.');
			}
		}

		return [$labels, $absolute];
	}
}
