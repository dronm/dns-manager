# Verification results

Version: 1.0.0

Verified with PHP 8.3.6 and BIND 9.18.39 on Linux.

## Automated checks

- 20 parser/model regression tests passed (`tests/run.php`).
- 14 integration checks passed (`tests/integration.php`).
- All 12 PHP files, including the executable entry point, passed syntax checks.

The integration suite starts an isolated BIND server on a random high port on
127.0.0.1, using `example.test` and a temporary TSIG key. It also uses controlled
process fixtures for error cases. The server and temporary files are removed
when the suite finishes. Tests ran with `php -n`.

Coverage includes exact-value deletion, preservation of unrelated records,
round trips for every supported record type, source comment preservation,
escaped names and quoted TXT values, dry runs, repeated commands repairing
drift, lock contention, missing-key preflight, update failures, retries,
timeouts, CNAME conflicts, and missing-TSIG verification errors.

## Supplied zone checks

- The annotated source preserves the supplied zone's record data.
- All 37 tagged records are initially enabled: 19 `sakko`, 14 `meln`, and
  4 `cloud` records.
- The source passes `named-checkzone` using the configured check-names policy.
- Disable dry runs for all three aliases select the expected records without
  modifying the source.

No production DNS updates were performed. The existing monitoring files were
not modified. These results verify the packaged application and test fixtures;
the deployment's BIND policy, key, connectivity, and permissions still need the
one-time setup described in `README.md`.
