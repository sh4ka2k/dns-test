# DNSAudit CLI

Command-line DNS security auditing powered by [dnsaudit.io](https://dnsaudit.io).

Run 26+ DNS security checks — DNSSEC, SPF, DKIM, DMARC, zone transfer tests, and more — directly from your terminal.

**Author:** Esteban Borges — [dnsaudit.io](https://dnsaudit.io)

## Requirements

- `bash` 4+
- [`curl`](https://curl.se)
- [`jq`](https://jqlang.github.io/jq/)

## Installation

```bash
git clone https://github.com/sh4ka2k/dns-test.git
cd dns-test
chmod +x dnsaudit.sh
# Optional: install globally
sudo ln -s "$PWD/dnsaudit.sh" /usr/local/bin/dnsaudit
```

## Authentication

```bash
export DNSAUDIT_API_KEY=dns_your_api_key_here
```

Or pass `--api-key KEY` with every command.

## Usage

```
dnsaudit <command> [options]
```

### scan

Run a full DNS security scan on a domain.

```bash
dnsaudit scan example.com
```

```
  DNS Security Audit: example.com
  2025-01-15T14:30:00.000Z

  Score: 85/100   Grade: B+

  23 passed   3 warnings   0 critical

  Check Results
  ────────────────────────────────────────
  ✔ SPF        [PASS]    Valid SPF record found
               v=spf1 include:_spf.google.com ~all
  ⚠ DMARC      [WARNING] DMARC policy set to none - consider quarantine or reject
               v=DMARC1; p=none
  ✔ DNSSEC     [PASS]    DNSSEC is properly configured
```

Output raw JSON:

```bash
dnsaudit scan example.com --json
```

### export

Export scan results as JSON or PDF.

```bash
# JSON to stdout
dnsaudit export example.com

# JSON to file
dnsaudit export example.com -o results.json

# PDF report
dnsaudit export example.com --format pdf -o report.pdf
```

### history

Show your recent scan history.

```bash
dnsaudit history
dnsaudit history --limit 50
dnsaudit history --json
```

## Options

| Option | Description |
|---|---|
| `--api-key KEY` | API key (overrides `$DNSAUDIT_API_KEY`) |
| `--json` | Output raw JSON |
| `--no-colour` | Disable ANSI colours |
| `--limit N` | History entries to return (default: 10, max: 100) |
| `--format json\|pdf` | Export format (default: json) |
| `-o, --output FILE` | Save output to FILE |

## Rate Limits

| Limit | Value |
|---|---|
| Daily scans | 20 per day (resets midnight UTC) |
| Burst | 10 requests per minute |

## License

MIT
