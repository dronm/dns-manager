<?php

declare(strict_types=1);

namespace DnsManager;

use InvalidArgumentException;

/**
 * A comment-preserving source inventory. No generated text replaces the source.
 */
final class ZoneSource {
	private readonly string $zoneName;

	/** @var array<int, array{text:string,eol:string}> */
	private array $lines = [];

	/** @var array<int, Record> */
	private array $managedRecords = [];

	public function __construct(
		private readonly string $sourceContents,
		string $zone,
	) {
		$this->zoneName = Record::normalizeName($zone, '.');

		if (str_contains($sourceContents, "\0")) {
			throw new InvalidArgumentException('Source contains a NUL byte.');
		}

		if (preg_match('/\r(?!\n)/', $sourceContents)) {
			throw new InvalidArgumentException('Use LF or CRLF line endings; bare CR is not supported.');
		}

		$parts = preg_split('/(\r\n|\n)/', $sourceContents, -1, PREG_SPLIT_DELIM_CAPTURE);

		if ($parts === false) {
			throw new InvalidArgumentException('Could not split source lines.');
		}

		for ($index = 0; $index < count($parts); $index += 2) {
			$this->lines[] = [
				'text' => $parts[$index],
				'eol' => $parts[$index + 1] ?? '',
			];
		}

		$this->parse();
	}

	/** @return array<int, Record> */
	public function records(?string $alias = null): array {
		if ($alias === null) {
			return $this->managedRecords;
		}

		$records = array_values(array_filter(
			$this->managedRecords,
			static fn (Record $record): bool => $record->alias === $alias,
		));

		if ($records === []) {
			throw new InvalidArgumentException('Unknown server alias: ' . $alias);
		}

		return $records;
	}

	/** @return array<string,array{enabled:int,disabled:int}> */
	public function aliases(): array {
		$aliases = [];

		foreach ($this->managedRecords as $record) {
			$aliases[$record->alias] ??= ['enabled' => 0, 'disabled' => 0];
			$aliases[$record->alias][$record->enabled ? 'enabled' : 'disabled']++;
		}

		ksort($aliases, SORT_STRING);
		return $aliases;
	}

	public function withState(string $alias, bool $enabled): string {
		$records = $this->records($alias);
		$lines = $this->lines;

		foreach ($records as $record) {
			if ($record->enabled === $enabled) {
				continue;
			}

			$lineIndex = $record->lineNumber - 1;
			$lines[$lineIndex]['text'] = $enabled
				? substr($lines[$lineIndex]['text'], 3)
				: ';! ' . $lines[$lineIndex]['text'];
		}

		$output = '';

		foreach ($lines as $line) {
			$output .= $line['text'] . $line['eol'];
		}

		return $output;
	}

	public function zone(): string {
		return $this->zoneName;
	}

	public function contents(): string {
		return $this->sourceContents;
	}

	private function parse(): void {
		$origin = $this->zoneName;
		$defaultTtl = null;
		$depth = 0;
		$identities = [];
		$rrsetTtls = [];

		foreach ($this->lines as $lineIndex => $line) {
			$lineNumber = $lineIndex + 1;
			$text = $line['text'];

			try {
				if (preg_match('/\A[ \t]+;!/', $text)) {
					throw new InvalidArgumentException('The reserved disabled prefix must start at column 1.');
				}

				$disabled = str_starts_with($text, ';! ');

				if (str_starts_with($text, ';!') && !$disabled) {
					throw new InvalidArgumentException('The disabled-record prefix must be exactly ";! ".');
				}

				$recordText = $disabled ? substr($text, 3) : $text;

				// Ordinary comments are never interpreted as disabled records.
				if (!$disabled && ($recordText === '' || preg_match('/\A[ \t]*(?:;.*)?\z/D', $recordText))) {
					continue;
				}

				[$body, $comment] = Record::splitComment($recordText);
				$alias = self::extractAlias($comment);

				if ($disabled && $alias === null) {
					throw new InvalidArgumentException('A disabled record requires an exact dm=ALIAS tag.');
				}

				if (trim($body, " \t") === '') {
					throw new InvalidArgumentException('A disabled or tagged line must contain a record.');
				}

				$depthBefore = $depth;
				$depth = self::parenthesisDepth($body, $depth);
				$hasParenthesis = self::hasParenthesis($body);

				if (($alias !== null || $disabled) && ($depthBefore > 0 || $hasParenthesis)) {
					throw new InvalidArgumentException('Managed records must be single-line records without parentheses.');
				}

				if ($depthBefore > 0) {
					continue;
				}

				if (str_starts_with(ltrim($body, " \t"), '$')) {
					if ($alias !== null || $disabled || $hasParenthesis) {
						throw new InvalidArgumentException('Directives cannot be tagged, disabled, or parenthesized.');
					}

					$tokens = Record::lex($body);

					if (count($tokens) !== 2 || $tokens[0]['quoted'] || $tokens[1]['quoted']) {
						throw new InvalidArgumentException('A source directive requires exactly one unquoted argument.');
					}

					$directive = strtoupper($tokens[0]['raw']);

					if ($directive === '$ORIGIN') {
						$origin = Record::normalizeName($tokens[1]['raw'], $origin);
					} elseif ($directive === '$TTL') {
						$defaultTtl = self::parseTtl($tokens[1]['raw']);
					} else {
						throw new InvalidArgumentException('Unsupported source directive: ' . $directive . '. Only $ORIGIN and $TTL are supported.');
					}

					continue;
				}

				if ($body[0] === ' ' || $body[0] === "\t") {
					throw new InvalidArgumentException('Every record statement must start with an explicit owner at column 1.');
				}

				$ownerToken = self::ownerToken($body);
				$owner = Record::normalizeName($ownerToken, $origin);

				if (!Record::isWithinZone($owner, $this->zoneName)) {
					throw new InvalidArgumentException('Record owner is outside the configured zone: ' . $owner);
				}

				// Only SOA may span lines. Otherwise a multiline unmanaged record
				// could hide a duplicate of a managed value from ownership checks.
				if ($hasParenthesis) {
					if (self::parenthesizedType($body) !== 'SOA') {
						throw new InvalidArgumentException('Only untagged SOA records may use parentheses or span multiple lines.');
					}

					continue;
				}

				[$record, $knownTtl] = $this->parseRecord(
					$body,
					$origin,
					$defaultTtl,
					$alias,
					$lineNumber,
					!$disabled,
				);

				if ($record === null) {
					continue;
				}

				$identity = $record->identity();
				$managed = $alias !== null;

				if (isset($identities[$identity]) && ($managed || $identities[$identity]['managed'])) {
					throw new InvalidArgumentException(
						'Duplicate record ownership overlaps line ' . $identities[$identity]['line']
						. '; a managed record must occur exactly once, including untagged copies.',
					);
				}

				$identities[$identity] ??= ['managed' => $managed, 'line' => $lineNumber];

				$rrset = $record->owner . "\t" . $record->type;

				if ($knownTtl !== null) {
					$rrsetTtls[$rrset] ??= ['values' => [], 'managed' => false];
					$previousTtls = $rrsetTtls[$rrset]['values'];

					if ($managed || $rrsetTtls[$rrset]['managed']) {
						foreach ($previousTtls as $previousTtl => $previousLine) {
							if ($previousTtl !== $knownTtl) {
								throw new InvalidArgumentException(
									'Records in the same name/type set must use one TTL; see line '
									. $previousLine . '.',
								);
							}
						}
					}

					$rrsetTtls[$rrset]['values'][$knownTtl] ??= $lineNumber;
					$rrsetTtls[$rrset]['managed'] = $rrsetTtls[$rrset]['managed'] || $managed;
				}

				if ($managed) {
					$this->managedRecords[] = $record;
				}
			} catch (InvalidArgumentException $error) {
				if (str_starts_with($error->getMessage(), 'Line ' . $lineNumber . ':')) {
					throw $error;
				}

				throw new InvalidArgumentException('Line ' . $lineNumber . ': ' . $error->getMessage(), 0, $error);
			}
		}

		if ($depth !== 0) {
			throw new InvalidArgumentException('Source has an unterminated parenthesized record.');
		}
	}

	/** @return array{?Record,?int} */
	private function parseRecord(
		string $body,
		string $origin,
		?int $defaultTtl,
		?string $alias,
		int $lineNumber,
		bool $enabled,
	): array {
		$tokens = Record::lex($body);

		if (count($tokens) < 3 || $tokens[0]['quoted']) {
			throw new InvalidArgumentException('Expected an owner, record type, and record data.');
		}

		$index = 1;
		$ttl = null;
		$explicitClass = false;
		$ttlRaw = null;

		for ($field = 0; $field < 2 && isset($tokens[$index]); $field++) {
			$raw = $tokens[$index]['raw'];

			if (!$tokens[$index]['quoted'] && strtoupper($raw) === 'IN' && !$explicitClass) {
				$explicitClass = true;
				$index++;
				continue;
			}

			if (!$tokens[$index]['quoted'] && preg_match('/\A[0-9]/', $raw) && $ttl === null) {
				$ttl = self::parseTtl($raw);
				$ttlRaw = $raw;
				$index++;
				continue;
			}

			break;
		}

		if (!isset($tokens[$index], $tokens[$index + 1]) || $tokens[$index]['quoted']) {
			throw new InvalidArgumentException('Record type or data is missing.');
		}

		$type = strtoupper($tokens[$index]['raw']);
		$rdata = substr($body, $tokens[$index + 1]['start']);

		if ($alias !== null) {
			if ($ttlRaw === null || !preg_match('/\A[0-9]+\z/D', $ttlRaw) || !$explicitClass) {
				throw new InvalidArgumentException('Managed records require an explicit numeric TTL and IN class.');
			}
		} elseif (!in_array($type, Record::SUPPORTED_TYPES, true)) {
			// BIND validates unmanaged record types; this parser never toggles them.
			return [null, null];
		}

		$effectiveTtl = $ttl ?? $defaultTtl;
		$record = Record::fromText(
			$tokens[0]['raw'],
			$effectiveTtl ?? 0,
			$type,
			$rdata,
			$origin,
			$this->zoneName,
			$alias ?? '',
			$lineNumber,
			$enabled,
		);

		return [$record, $effectiveTtl];
	}

	private static function extractAlias(string $comment): ?string {
		$count = preg_match_all('/(?:\A|[ \t;])dm\b/i', $comment, $matches, PREG_OFFSET_CAPTURE);

		if ($count === 0) {
			return null;
		}

		if ($count !== 1) {
			throw new InvalidArgumentException('A record may have only one dm=ALIAS tag.');
		}

		$matched = $matches[0][0];
		$offset = $matched[1] + strlen($matched[0]) - 2;
		$tail = substr($comment, $offset);

		if (!preg_match('/\Adm=([A-Za-z0-9][A-Za-z0-9._-]{0,63})(?=\z|[ \t;])/', $tail, $alias)) {
			throw new InvalidArgumentException('Malformed manager tag; use exactly dm=ALIAS.');
		}

		return $alias[1];
	}

	private static function ownerToken(string $body): string {
		$length = strlen($body);
		$index = 0;

		while ($index < $length) {
			if ($body[$index] === '\\') {
				$index += 2;
				continue;
			}

			if ($body[$index] === ' ' || $body[$index] === "\t") {
				break;
			}

			$index++;
		}

		return substr($body, 0, $index);
	}

	private static function parseTtl(string $value): int {
		if (preg_match('/\A[0-9]+\z/D', $value)) {
			$normalized = ltrim($value, '0');
			$normalized = $normalized === '' ? '0' : $normalized;

			if (strlen($normalized) > 10
				|| (strlen($normalized) === 10 && strcmp($normalized, '2147483647') > 0)) {
				throw new InvalidArgumentException('TTL must be between 0 and 2147483647.');
			}

			return (int) $normalized;
		}

		if (!preg_match('/\A(?:[0-9]+[wdhms])+\z/Di', $value)) {
			throw new InvalidArgumentException('Invalid TTL value.');
		}

		preg_match_all('/([0-9]+)([wdhms])/i', $value, $parts, PREG_SET_ORDER);
		$units = ['w' => 604800, 'd' => 86400, 'h' => 3600, 'm' => 60, 's' => 1];
		$seconds = 0;

		foreach ($parts as $part) {
			$amount = self::parseTtl($part[1]);
			$multiplier = $units[strtolower($part[2])];

			if ($amount > intdiv(2147483647 - $seconds, $multiplier)) {
				throw new InvalidArgumentException('TTL must be between 0 and 2147483647.');
			}

			$seconds += $amount * $multiplier;
		}

		return $seconds;
	}

	private static function parenthesisDepth(string $body, int $depth): int {
		$quoted = false;

		for ($index = 0; $index < strlen($body); $index++) {
			$character = $body[$index];

			if ($character === '\\') {
				$index++;
				continue;
			}

			if ($character === '"') {
				$quoted = !$quoted;
				continue;
			}

			if (!$quoted) {
				if ($character === '(') {
					$depth++;
				} elseif ($character === ')') {
					$depth--;

					if ($depth < 0) {
						throw new InvalidArgumentException('Unexpected closing parenthesis.');
					}
				}
			}
		}

		return $depth;
	}

	private static function parenthesizedType(string $body): string {
		$quoted = false;
		$offset = null;

		for ($index = 0; $index < strlen($body); $index++) {
			if ($body[$index] === '\\') {
				$index++;
				continue;
			}

			if ($body[$index] === '"') {
				$quoted = !$quoted;
			} elseif (!$quoted && ($body[$index] === '(' || $body[$index] === ')')) {
				$offset = $index;
				break;
			}
		}

		if ($offset === null) {
			return '';
		}

		$tokens = Record::lex(substr($body, 0, $offset));
		$index = 1;
		$hasTtl = false;
		$hasClass = false;

		for ($field = 0; $field < 2 && isset($tokens[$index]); $field++) {
			$raw = $tokens[$index]['raw'];

			if (!$tokens[$index]['quoted'] && strtoupper($raw) === 'IN' && !$hasClass) {
				$hasClass = true;
				$index++;
			} elseif (!$tokens[$index]['quoted'] && preg_match('/\A[0-9]/', $raw) && !$hasTtl) {
				self::parseTtl($raw);
				$hasTtl = true;
				$index++;
			} else {
				break;
			}
		}

		return isset($tokens[$index]) && !$tokens[$index]['quoted']
			? strtoupper($tokens[$index]['raw'])
			: '';
	}

	private static function hasParenthesis(string $body): bool {
		$quoted = false;

		for ($index = 0; $index < strlen($body); $index++) {
			if ($body[$index] === '\\') {
				$index++;
				continue;
			}

			if ($body[$index] === '"') {
				$quoted = !$quoted;
			} elseif (!$quoted && ($body[$index] === '(' || $body[$index] === ')')) {
				return true;
			}
		}

		return false;
	}
}
