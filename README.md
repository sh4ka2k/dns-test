# DNSAudit CLI

A command-line tool for DNS security auditing powered by the [dnsaudit.io](https://dnsaudit.io) API.

Run 26+ DNS security checks — DNSSEC, SPF, DKIM, DMARC, zone transfer tests, and more — directly from your terminal.

## Installation

**Requirements:** Python 3.10+

```bash
pip install -r requirements.txt
pip install -e .
```

## Authentication

Set your API key as an environment variable:

```bash
export DNSAUDIT_API_KEY=dns_your_api_key_here
```

Or pass it with every command using `--api-key`.

## Usage

### Scan a domain

```bash
dnsaudit scan example.com
```

```
  DNS Security Audit: example.com
  2025-01-15T14:30:00.000Z

  Score: 85/100  Grade: B+

  23 passed  3 warnings  0 critical

  Check Results
  ----------------------------------------
  ✔ SPF        [PASS]     Valid SPF record found
               v=spf1 include:_spf.google.com ~all
  ⚠ DMARC      [WARNING]  DMARC policy set to none - consider quarantine or reject
               v=DMARC1; p=none
  ✔ DNSSEC     [PASS]     DNSSEC is properly configured
```

Output raw JSON:

```bash
dnsaudit scan example.com --json
```

### Export results

```bash
# JSON export to stdout
dnsaudit export example.com

# JSON export to file
dnsaudit export example.com -o results.json

# PDF report
dnsaudit export example.com --format pdf -o report.pdf
```

### View scan history

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

## Rate Limits

| Limit | Value |
|---|---|
| Daily scans | 20 per day (resets midnight UTC) |
| Burst | 10 requests per minute |

## License

MIT
