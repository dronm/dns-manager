<?php

declare(strict_types=1);

namespace DnsManager;

use InvalidArgumentException;
use Throwable;

final class Application
{
	public static function run(array $arguments, string $defaultConfig): int
	{
		$store = null;
		$desiredSaved = false;
		try {
			$options = self::options(array_slice($arguments, 1), $defaultConfig);
			if ($options['help']) {
				self::help();
				return 0;
			}
			if ($options['version']) {
				fwrite(STDOUT, "dns-manager 1.0.0\n");
				return 0;
			}
			$config = new Config($options['config'], $options['zone']);
			$store = new SourceStore($config->sourceFile, $config->lockTimeout);
			$original = $store->read();
			$source = new ZoneSource($original, $config->zone);
			$action = $options['action'];
			if ($action === 'status') {
				$aliases = $source->aliases();
				if ($options['alias'] !== null) {
					if (!isset($aliases[$options['alias']])) {
						throw new InvalidArgumentException('Unknown alias: ' . $options['alias']);
					}
					$aliases = [$options['alias'] => $aliases[$options['alias']]];
				}
				fwrite(STDOUT, 'Desired source state for ' . $config->zone . " (BIND was not queried):\n");
				foreach ($aliases as $alias => $counts) {
					fwrite(STDOUT, sprintf("%s\tenabled=%d\tdisabled=%d\n", $alias, $counts['enabled'], $counts['disabled']));
				}
				if ($aliases === []) {
					fwrite(STDOUT, "No tagged records.\n");
				}
				return 0;
			}
			$client = new BindClient($config);
			if ($action === 'validate') {
				$client->validate($original);
				fwrite(STDOUT, sprintf("Valid source for %s: %d tagged records, %d aliases. No DNS update sent.\n", $config->zone, count($source->records()), count($source->aliases())));
				return 0;
			}
			$alias = $options['alias'];
			$records = $source->records($alias);
			if ($records === []) {
				throw new InvalidArgumentException('Unknown alias or no tagged records: ' . $alias);
			}
			$enabled = $action === 'enable';
			$candidate = $source->withState($alias, $enabled);
			new ZoneSource($candidate, $config->zone);
			$client->validate($candidate);
			if ($options['dry_run']) {
				fwrite(STDOUT, sprintf("DRY RUN: %s %d records for %s in %s. Source unchanged; no DNS update sent.\n", $action, count($records), $alias, $config->zone));
				fwrite(STDOUT, $client->input($records, $enabled));
				return 0;
			}
			$client->preflight();
			$changed = $store->save($original, $candidate);
			$desiredSaved = true;
			$client->apply($records, $enabled);
			fwrite(STDOUT, sprintf("%s %d records for %s in %s; verified on %s:%d. Source %s.\n", $enabled ? 'Enabled' : 'Disabled', count($records), $alias, $config->zone, $config->server, $config->port, $changed ? 'updated' : 'already matched; DNS was reapplied'));
			return 0;
		} catch (Throwable $error) {
			fwrite(STDERR, 'ERROR: ' . $error->getMessage() . "\n");
			if ($desiredSaved) {
				fwrite(STDERR, "Desired state remains in the source file. BIND application is failed or unverified; retry the same command. A timeout can mean the update was already accepted.\n");
				return 4;
			}
			return 2;
		} finally {
			$store?->close();
		}
	}

	private static function options(array $arguments, string $defaultConfig): array
	{
		$options = ['config' => $defaultConfig, 'zone' => null, 'dry_run' => false, 'help' => false, 'version' => false, 'action' => null, 'alias' => null];
		$positionals = [];
		$seen = [];
		$endOptions = false;
		for ($index = 0; $index < count($arguments); $index++) {
			$value = $arguments[$index];
			if (!$endOptions && $value === '--') {
				$endOptions = true;
				continue;
			}
			if (!$endOptions && ($value === '--help' || $value === '-h')) {
				$options['help'] = true;
				continue;
			}
			if (!$endOptions && $value === '--version') {
				$options['version'] = true;
				continue;
			}
			if (!$endOptions && $value === '--dry-run') {
				$options['dry_run'] = true;
				continue;
			}
			if (!$endOptions && preg_match('/^--(config|zone)(?:=(.*))?$/D', $value, $matches) === 1) {
				$name = $matches[1];
				if (isset($seen[$name])) {
					throw new InvalidArgumentException('Option supplied twice: --' . $name);
				}
				$seen[$name] = true;
				$optionValue = $matches[2] ?? ($arguments[++$index] ?? '');
				if ($optionValue === '' || str_starts_with($optionValue, '--')) {
					throw new InvalidArgumentException('Missing value for --' . $name);
				}
				$options[$name] = $optionValue;
				continue;
			}
			if (!$endOptions && str_starts_with($value, '-')) {
				throw new InvalidArgumentException('Unknown option: ' . $value);
			}
			$positionals[] = $value;
		}
		if ($options['help'] || $options['version']) {
			return $options;
		}
		if ($positionals === []) {
			throw new InvalidArgumentException('Specify an action. Use --help for usage.');
		}
		if (in_array($positionals[0], ['enable', 'disable', 'status', 'validate'], true)) {
			$options['action'] = array_shift($positionals);
			$options['alias'] = array_shift($positionals);
		} elseif (count($positionals) === 2 && in_array($positionals[1], ['enable', 'disable', 'status'], true)) {
			$options['alias'] = array_shift($positionals);
			$options['action'] = array_shift($positionals);
		} else {
			throw new InvalidArgumentException('Use ALIAS enable|disable, status [ALIAS], or validate.');
		}
		if ($positionals !== [] || ($options['action'] === 'validate' && $options['alias'] !== null)) {
			throw new InvalidArgumentException('Unexpected positional arguments.');
		}
		if (in_array($options['action'], ['enable', 'disable'], true) && $options['alias'] === null) {
			throw new InvalidArgumentException('The enable/disable action requires an alias.');
		}
		if ($options['alias'] !== null && preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/D', $options['alias']) !== 1) {
			throw new InvalidArgumentException('Invalid alias.');
		}
		if ($options['dry_run'] && !in_array($options['action'], ['enable', 'disable'], true)) {
			throw new InvalidArgumentException('--dry-run applies only to enable/disable.');
		}
		return $options;
	}

	private static function help(): void
	{
		fwrite(STDOUT, <<<'HELP'
dns-manager 1.0.0 - Toggle tagged DNS records from an annotated zone source.

Usage:
  dns-manager [--config FILE] [--zone ZONE] ALIAS enable|disable [--dry-run]
  dns-manager [--config FILE] [--zone ZONE] enable|disable ALIAS [--dry-run]
  dns-manager [--config FILE] [--zone ZONE] status [ALIAS]
  dns-manager [--config FILE] [--zone ZONE] validate

The default configuration is dns-manager.json beside the executable.
Omit --zone only when exactly one zone is configured.
Records end with ; dm=ALIAS. Disabled tagged records start with ;! at column 1.
Status shows desired source state only. Dry runs validate but never send updates.
Actual changes require nsupdate, named-checkzone, dig, and a readable TSIG key.
Exit codes: 0 success; 2 input/local validation failure; 4 desired state saved,
but the DNS change failed or could not be verified. Retry the same command.

HELP);
	}
}
