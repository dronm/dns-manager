<?php

declare(strict_types=1);

require __DIR__ . '/../src/Record.php';
require __DIR__ . '/../src/ZoneSource.php';
require __DIR__ . '/TestSupport.php';

use DnsManager\Record;
use DnsManager\ZoneSource;
use DnsManager\Tests\Suite;
use function DnsManager\Tests\expect;
use function DnsManager\Tests\fixture;
use function DnsManager\Tests\same;
use function DnsManager\Tests\throws;

$suite = new Suite();

$suite->test('Aliases include only actual trailing metadata comments', static function (): void {
	$source = new ZoneSource(fixture(), 'example.test');
	same(['meln', 'other', 'sakko'], array_keys($source->aliases()), 'Unexpected aliases');
	same(6, count($source->records('meln')), 'Wrong meln record count');
});

$suite->test('Disable selects exact alias and leaves infrastructure untouched', static function (): void {
	$source = new ZoneSource(fixture(), 'example.test');
	$changed = $source->withState('meln', false);
	same(6, substr_count($changed, ';! '), 'Not all meln records disabled');
	expect(str_contains($changed, "www 60 IN A 192.0.2.10 ; dm=sakko\n"), 'Other backend changed');
	expect(str_contains($changed, "ns3 3600 IN A 192.0.2.20 ; infrastructure"), 'Infrastructure address changed');
	expect(str_contains($changed, '; This ordinary comment must survive every operation.'), 'Ordinary comment changed');
});

$suite->test('Disable then enable restores original bytes', static function (): void {
	$original = fixture();
	$disabled = (new ZoneSource($original, 'example.test'))->withState('meln', false);
	same($original, (new ZoneSource($disabled, 'example.test'))->withState('meln', true), 'Enable lost formatting or data');
});

$suite->test('Repeated source toggle is idempotent', static function (): void {
	$disabled = (new ZoneSource(fixture(), 'example.test'))->withState('meln', false);
	same($disabled, (new ZoneSource($disabled, 'example.test'))->withState('meln', false), 'Repeated disable changes bytes');
});

$suite->test('CRLF formatting is preserved', static function (): void {
	$original = str_replace("\n", "\r\n", fixture());
	$disabled = (new ZoneSource($original, 'example.test'))->withState('meln', false);
	same($original, (new ZoneSource($disabled, 'example.test'))->withState('meln', true), 'CRLF source did not round-trip');
});

$suite->test('Unknown alias fails instead of succeeding with zero changes', static function (): void {
	throws(static fn () => (new ZoneSource(fixture(), 'example.test'))->withState('mel', false), 'Alias typo was accepted');
});

$suite->test('Deletion always includes the exact record data', static function (): void {
	$record = Record::fromText('www', 60, 'A', '192.0.2.20', 'example.test.', 'example.test.', 'meln');
	same('update delete www.example.test. IN A 192.0.2.20', $record->renderUpdate(false), 'Unsafe deletion');
});

$suite->test('Relative RDATA names become absolute before nsupdate', static function (): void {
	$record = Record::fromText('_service._tcp', 60, 'SRV', '10 5 443 api', 'example.test.', 'example.test.');
	expect(str_ends_with($record->rdata, 'api.example.test.'), 'Relative SRV target not normalized');
	$mx = Record::fromText('@', 60, 'MX', '10 mail', 'example.test.', 'example.test.');
	expect(str_ends_with($mx->rdata, 'mail.example.test.'), 'Relative MX target not normalized');
});

$suite->test('IPv6 identity is independent of textual compression', static function (): void {
	$first = Record::fromText('v6', 60, 'AAAA', '2001:db8::1', 'example.test.', 'example.test.');
	$second = Record::fromText('v6.example.test.', 3600, 'AAAA', '2001:0db8:0:0:0:0:0:1', 'example.test.', 'example.test.');
	same($first->identity(), $second->identity(), 'Semantically identical IPv6 records differ');
});

$suite->test('DNS text escapes normalize without treating quoted semicolons as comments', static function (): void {
	$first = Record::fromText('txt', 60, 'TXT', '"a;b"', 'example.test.', 'example.test.');
	$second = Record::fromText('txt', 60, 'TXT', '"a\\059b"', 'example.test.', 'example.test.');
	same($first->identity(), $second->identity(), 'Equivalent TXT escape spellings differ');
});

$suite->test('TXT string boundaries remain significant', static function (): void {
	$first = Record::fromText('txt', 60, 'TXT', '"ab" "cd"', 'example.test.', 'example.test.');
	$second = Record::fromText('txt', 60, 'TXT', '"abcd"', 'example.test.', 'example.test.');
	expect($first->identity() !== $second->identity(), 'Distinct TXT wire values were merged');
});

$suite->test('Update-command injection is rejected', static function (): void {
	throws(static fn () => Record::fromText('www', 60, 'A', "192.0.2.20\nsend", 'example.test.', 'example.test.'), 'Newline injection accepted');
});

$suite->test('Inherited owner names are rejected even on untagged records', static function (): void {
	throws(static fn () => new ZoneSource(fixture() . "\t60 IN A 192.0.2.99\n", 'example.test'), 'Inherited owner accepted');
});

$suite->test('Include directives cannot hide managed data outside the source', static function (): void {
	throws(static fn () => new ZoneSource(fixture() . '$INCLUDE /tmp/other.zone' . "\n", 'example.test'), 'Include directive accepted');
});

$suite->test('Managed records outside the selected zone are rejected', static function (): void {
	throws(static fn () => new ZoneSource(fixture() . "outside.invalid. 60 IN A 192.0.2.20 ; dm=meln\n", 'example.test'), 'Out-of-zone record accepted');
});

$suite->test('One record cannot be assigned to two aliases', static function (): void {
	throws(static fn () => new ZoneSource(fixture() . "www 60 IN A 192.0.2.20 ; dm=other\n", 'example.test'), 'Duplicate record ownership accepted');
});

$suite->test('Managed multiline records are rejected explicitly', static function (): void {
	throws(static fn () => new ZoneSource(fixture() . "multi 60 IN TXT ( ; dm=meln\n\t\"text\"\n)\n", 'example.test'), 'Managed multiline record accepted');
});

$suite->test('Untagged multiline records cannot bypass managed ownership checks', static function (): void {
	$source = fixture() . "www 60 IN A (\n\t192.0.2.20\n)\n";
	throws(static fn () => new ZoneSource($source, 'example.test'), 'Parenthesized duplicate bypassed ownership checks');
});

$suite->test('SOA cannot be attached to a failover alias', static function (): void {
	throws(static fn () => Record::fromText('@', 3600, 'SOA', 'ns1 hostmaster 1 3600 600 604800 300', 'example.test.', 'example.test.', 'meln'), 'Managed SOA accepted');
});

$suite->test('Delegation NS records stay outside failover management', static function (): void {
	throws(static fn () => new ZoneSource(fixture() . "child 3600 IN NS ns1.example.test. ; dm=meln\n", 'example.test'), 'Managed delegation NS accepted');
});

exit($suite->finish());
