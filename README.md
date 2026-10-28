# dns-manager

A small PHP CLI for enabling or disabling explicitly tagged DNS records in BIND. The editable source is an ordinary zone file with comments. The application sends exact additions or deletions through `nsupdate`, then checks the authoritative server with `dig`.

The CLI handles record changes. Health checks, scheduling, and notifications belong in the caller.

## Requirements

- Linux or another Unix-like system with PHP CLI 8.1 or newer.
- PHP's standard JSON, process, stream, and filesystem functions; no Composer packages or PHP framework.
- BIND client utilities: `nsupdate`, `named-checkzone`, and `dig`.
- An authoritative BIND primary configured to accept this application's TSIG-signed updates.
- A service account able to read the TSIG key and atomically replace its own source file.

On Debian or Ubuntu, the required packages are typically:

```bash
sudo apt-get install php-cli bind9-dnsutils bind9-utils
```

## Quick start

The project includes `dns-manager.example.json` and `zones/example.org.zone`. They use the example domain `example.org`, aliases `web1` and `web2`, and documentation IP addresses.

From the project directory, select the example configuration explicitly:

```bash
php dns-manager --help
php dns-manager --config dns-manager.example.json --zone example.org status
php dns-manager --config dns-manager.example.json --zone example.org validate
php dns-manager --config dns-manager.example.json --zone example.org web2 disable --dry-run
```

These commands inspect or validate the example source and preview changes without publishing DNS updates. Validation and dry runs require the configured BIND utilities. They do not require a TSIG key or a running DNS server.

For a local test BIND instance serving `example.org`, after completing the authentication setup below, commands that publish changes are:

```bash
php dns-manager --config dns-manager.example.json --zone example.org web2 disable
php dns-manager --config dns-manager.example.json --zone example.org web2 enable
```

The command accepts both `web2 disable` and `disable web2`. Aliases are matched exactly. If an alias is itself a command word, use action-first syntax; for example, `disable enable` disables the alias named `enable`.

The executable can also be invoked directly after `chmod +x dns-manager` when `php` is on `PATH`.

## Source file and record tags

`zones/example.org.zone` is an example of the application's editable source. It is independent of BIND's live zone file, such as `/var/lib/bind/db.example.org`. **Do not point BIND's zone `file` setting at the annotated source, or point this application's `source_file` at BIND's live file.**

An enabled managed record has a trailing alias tag:

```text
api	60	IN	A	192.0.2.20	; dm=web2
```

A disabled managed record has the reserved `;! ` prefix at the start of its line:

```text
;! api	60	IN	A	192.0.2.20	; dm=web2
```

The manager adds or removes that prefix and preserves the rest of the source. Ordinary comments are never uncommented. Untagged records are outside its control, even if they contain a managed server's IP address.

For example:

```text
api	60	IN	A	192.0.2.10	; dm=web1
api	60	IN	A	192.0.2.20	; dm=web2
ns2	3600	IN	A	192.0.2.54	; DNS infrastructure
```

Disabling `web2` withdraws its tagged `api` address while preserving the `web1` value and the untagged nameserver record. The command also processes every other record tagged `web2` in the selected source.

### Source format rules

- A managed record occupies one physical line and explicitly supplies its owner, numeric TTL, class `IN`, type, and data.
- Start every record statement with its explicit owner at column 1. Inherited owners are rejected because commenting out a preceding record could change their meaning.
- Only the untagged SOA may be multiline or parenthesized. Other records must occupy one physical line, including untagged records; this keeps ownership checks unambiguous.
- `$ORIGIN` and `$TTL` are supported. `$INCLUDE` and `$GENERATE` are rejected.
- Each managed record has exactly one valid `dm=alias` tag in an actual comment. A semicolon or tag-like string inside quoted TXT data is not metadata.
- Aliases consist of letters, digits, `.`, `_`, and `-`, with a letter or digit first. They are case-sensitive.
- Managed names must belong to the selected zone. Relative owner names and domain-name data are expanded using the current `$ORIGIN`.
- Duplicate managed record definitions, including assigning the same record to multiple aliases, are rejected.
- SOA, all NS records, and DNSSEC maintenance records must remain untagged. BIND owns the live SOA serial and its signing records. Delegation NS records are excluded because ordinary authoritative-answer verification cannot reliably verify them.

Supported managed types are `A`, `AAAA`, `CNAME`, `PTR`, `DNAME`, `MX`, `SRV`, `TXT`, `CAA`, `SSHFP`, and `TLSA`. The example source manages A and AAAA records. When adding another supported type, also grant that type and owner in BIND's update policy. Other types are rejected explicitly.

Tags associate records directly with an alias; they do not infer dependencies from an IP. A shared CNAME can remain untagged while its target's A/AAAA values change. Tagged records can be unrelated to an IP when their type allows it.

### Example zone

Each example alias supplies an A record and an AAAA record for both `example.org` and `api.example.org`:

| Alias | IPv4 address | IPv6 address | Managed records | Initial state |
| --- | --- | --- | ---: | --- |
| `web1` | `192.0.2.10` | `2001:db8::10` | 4 | Enabled |
| `web2` | `192.0.2.20` | `2001:db8::20` | 4 | Enabled |

The SOA, NS records, nameserver and mail-server addresses, MX and TXT records, and shared `www` CNAME are untagged. The CNAME points `www.example.org` to `example.org`, so the address records are maintained at the target rather than duplicated for `www`.

The source records desired state. Changes made directly to BIND or by another DNS client do not automatically change this file.

## Configuration

The application loads `dns-manager.json` beside the executable by default. Select another file with `--config /absolute/path/to/config.json`. All record-management command examples in this README explicitly select `dns-manager.example.json`.

For a fresh installation with no local configuration, copy the example to `dns-manager.json`:

```bash
cp -i dns-manager.example.json dns-manager.json
```

Adapt the zone name, source path, DNS server, key path, and source records to your installation before publishing updates. Keep the annotated source separate from BIND's live file. The example configuration is:

```json
{
	"binaries": {
		"nsupdate": "nsupdate",
		"named_checkzone": "named-checkzone",
		"dig": "dig"
	},
	"timeout_sec": 15,
	"lock_timeout_sec": 5,
	"zones": {
		"example.org": {
			"source_file": "zones/example.org.zone",
			"server": "127.0.0.1",
			"port": 53,
			"key_file": "/etc/dns-manager/update.key",
			"check_names": "fail"
		}
	}
}
```

Paths to source and key files are resolved relative to the configuration file when they are not absolute. Binary names may be resolved through `PATH`, or replaced with absolute executable paths.

Set `server` to the writable authoritative primary. The example's `127.0.0.1` assumes the CLI runs on that primary; change it when running remotely. The account must be permitted to query that same server for authoritative verification. If you use BIND views, configure the key and source address so update and verification requests reach the intended view.

The `check_names` value controls local `named-checkzone` validation and accepts `fail`, `warn`, or `ignore`. The example uses `fail`. Set the live BIND zone's `check-names` policy consistently; changing the JSON setting does not change BIND's configuration.

The source directory must be writable by the CLI account. Atomic replacement and the adjacent lock file require directory write permission in addition to access to the source itself. Existing source ownership and permissions are retained when the source is replaced.

## BIND authentication setup

The following configuration is for a local example zone on the writable BIND primary. The live zone must already contain its SOA, NS records, and other initial data; the manager does not create zones or publish untagged records. When adapting these steps to an existing zone, preserve its transfer, DNSSEC, ACL, view, and other settings and merge the update-policy entries into that zone's existing definition.

### 1. Create a TSIG key

For a typical Debian/Ubuntu BIND installation using the `bind` group:

```bash
sudo sh -c 'umask 027; set -C; tsig-keygen -a hmac-sha256 dns-manager > /etc/bind/dns-manager.key'
sudo chown root:bind /etc/bind/dns-manager.key
sudo chmod 0640 /etc/bind/dns-manager.key
```

The key name in this example is `dns-manager`; it must match the policy identity below. `set -C` prevents overwriting an existing key. Keep key files out of version control. The key is supplied to the tools through `-k`, not as a secret embedded in command arguments or JSON.

### 2. Grant the example application names and record types

Add the key include at the appropriate top level in BIND's configuration:

```text
include "/etc/bind/dns-manager.key";
```

Merge the following into the existing primary zone block:

```text
zone "example.org" {
	type primary;
	file "/var/lib/bind/db.example.org";
	check-names fail;

	update-policy {
		grant dns-manager name example.org. A AAAA;
		grant dns-manager name api.example.org. A AAAA;
	};
};
```

This policy matches every managed record in the example source. It omits the nameserver addresses and shared CNAME and does not grant other record types. Existing certificate automation can keep its own separately scoped key and policy entries. BIND does not permit both `allow-update` and `update-policy` in the same zone, so preserve any existing update clients when migrating that setting.

A per-name/type BIND rule cannot distinguish `web1`'s address from `web2`'s at the same owner. The application performs that exact-value selection; BIND limits the names and types the key can affect.

Validate the server configuration and load the policy:

```bash
sudo named-checkconf && sudo rndc reconfig
```

BIND must be able to write the live zone directory and journal. Normal application commands use `nsupdate`; they do not run `sudo`, `rndc freeze`, `rndc thaw`, or edit the live zone file.

### 3. Install the CLI under a dedicated account

For a new installation, run the following from the project directory. The example assumes the service account does not already exist and `/opt/dns-manager` is a fresh destination. It installs the application and example files explicitly:

```bash
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin dns-manager
sudo install -d -o root -g root -m 0755 /opt/dns-manager
sudo install -o root -g root -m 0755 dns-manager /opt/dns-manager/dns-manager
sudo cp -a src /opt/dns-manager/src
sudo chown -R root:root /opt/dns-manager/src
sudo install -o root -g root -m 0644 dns-manager.example.json /opt/dns-manager/dns-manager.example.json
sudo install -d -o dns-manager -g dns-manager -m 0750 /opt/dns-manager/zones
sudo install -o dns-manager -g dns-manager -m 0640 zones/example.org.zone /opt/dns-manager/zones/example.org.zone
sudo install -d -o root -g dns-manager -m 0750 /etc/dns-manager
sudo install -o root -g dns-manager -m 0640 /etc/bind/dns-manager.key /etc/dns-manager/update.key
```

Generate the key once and copy that same file for the client. The client copy is readable by the CLI account and writable only by root. For a remote CLI, transfer this client's key through your existing secure administration channel. Keep both copies consistent when rotating it.

Check the deployed configuration, then inspect the planned operation:

```bash
sudo -u dns-manager /opt/dns-manager/dns-manager --config /opt/dns-manager/dns-manager.example.json --zone example.org validate
sudo -u dns-manager /opt/dns-manager/dns-manager --config /opt/dns-manager/dns-manager.example.json --zone example.org web2 disable --dry-run
```

For your own deployment, install an adapted configuration and source, then select that configuration explicitly. Test the setup against a separate test zone before making a production change. Disabling an alias may remove the last address of a name served by only that alias.

## Commands

```bash
php dns-manager --config dns-manager.example.json --zone example.org status
php dns-manager --config dns-manager.example.json --zone example.org web2 status
php dns-manager --config dns-manager.example.json --zone example.org validate
php dns-manager --config dns-manager.example.json --zone example.org web2 disable --dry-run
php dns-manager --config dns-manager.example.json --zone example.org web2 disable
php dns-manager --config dns-manager.example.json --zone example.org web2 enable
```

Exit codes are `0` for success, `2` for an input or local validation failure before the desired state is saved, and `4` when the desired state is saved but the DNS update fails or cannot be verified.

`status` reports the source's desired enabled/disabled counts. It is not a live DNS health check or a claim that an earlier update succeeded.

`validate` checks the source and its format without applying DNS changes. `--dry-run` shows the requested record operations without changing source markers or submitting an update.

`enable` and `disable` operate on all records carrying the selected alias. They preserve unrelated record values at shared owners. They are immediate operations, not persistent maintenance overrides: a future caller can issue the opposite operation. Callers determine when to request those operations.

The tool does not automatically import the zone, publish untagged records, discover new names, generate `www` records, or reconcile arbitrary edits to record names/values. To replace or remove an existing managed record definition, disable its old definition before changing it, then enable the intended new definition. Keep a backup before editing the source by hand, and avoid editing while a command is running.

## Failure and retry behavior

A mutation validates the proposed source, saves its desired markers atomically, submits one update request, then verifies the selected records directly on the authoritative server. External commands have bounded execution time and are invoked without a shell. A lock serializes operations using the same source file.

The source file and BIND cannot form one atomic transaction. If publishing fails after saving the source, the source retains the requested state and the command returns a nonzero exit status. A timeout can mean the result is uncertain, including that BIND accepted the update before the response was lost.

**Repeat the same command to retry.** It still submits or verifies the requested DNS state when the comment markers already match. A matching local comment is never treated as proof that the DNS update succeeded.

Verification checks the selected authoritative server, not every secondary or recursive cache. Other servers and clients may temporarily retain older data according to zone-transfer and cache behavior. BIND handles the live SOA serial; toggle operations do not edit the source SOA serial.

## Name validation

The example uses `check_names: "fail"` and `check-names fail;` on BIND. For an existing zone that deliberately permits nonstandard hostnames, choose the appropriate policy in both places.

After validating the full source with `named-checkzone`, the updater disables `nsupdate`'s separate client-side name check so it does not silently omit an individual record. Server policy and authoritative verification still apply. `check-integrity` controls different checks, including MX/SRV targets and delegation glue, and is not a replacement for the name-validation setting.

## Tests

Run the parser and model regression tests from the project directory:

```bash
php tests/run.php
```

The integration suite starts its own BIND instance on `127.0.0.1` using an unprivileged port. It creates temporary zone, source, and key files and never loads your production configuration:

```bash
php tests/integration.php
```

Integration tests additionally require the `named` executable, normally provided by the `bind9` package on Debian/Ubuntu. They do not need root or port 53.

For a custom test installation, these optional environment variables override executable paths: `DNS_MANAGER_NSUPDATE_BINARY`, `DNS_MANAGER_DIG_BINARY`, `DNS_MANAGER_CHECKZONE_BINARY`, and `DNS_MANAGER_NAMED_BINARY`.

## References

- [BIND `nsupdate` and `named-checkzone` manuals](https://bind9.readthedocs.io/en/stable/manpages.html)
- [BIND dynamic updates and journal files](https://bind9.readthedocs.io/en/stable/chapter6.html#dynamic-update)
- [BIND update-policy and validation settings](https://bind9.readthedocs.io/en/stable/reference.html)
- [PHP `proc_open`: argument arrays avoid a shell](https://www.php.net/manual/en/function.proc-open.php)
