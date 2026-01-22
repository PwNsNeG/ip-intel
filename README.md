ip-enrich

ip-enrich is a simple CLI tool that enriches IP addresses with threat intelligence and network context, producing structured JSON reports suitable for automation and analysis.

It is designed to be CLI-first, scriptable, and easy to integrate into security workflows.

Features

Enrich a single IP or a file containing multiple IPs

Fetch reputation data from AbuseIPDB

Add basic network context (ASN, organization, geo)

Generate an explainable risk score (0–100)

Output clean, structured JSON

Batch-friendly and automation-ready

Input / Output
Input

A single IPv4/IPv6 address

A text file containing one IP per line

Output

JSON to stdout or to a file

One normalized report per IP

Batch mode returns an array with processing statistics

Installation
git clone https://github.com/<your-username>/ip-enrich.git
cd ip-enrich
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

Configuration

Create a .env file (not tracked by git):

ABUSEIPDB_API_KEY=your_api_key_here
ABUSEIPDB_MAX_AGE_DAYS=90
ABUSEIPDB_VERBOSE=false
REQUEST_TIMEOUT_SECONDS=15


A template is provided in .env.example.

Usage
Enrich a single IP
ip-enrich 1.2.3.4

Enrich a file of IPs
ip-enrich --file ips.txt

Write output to a file
ip-enrich 1.2.3.4 --out report.json

Disable raw provider output
ip-enrich 1.2.3.4 --no-raw

Output format (example)
{
  "indicator": { "type": "ip", "ip": "1.2.3.4" },
  "timestamp": "2026-01-22T12:34:56Z",
  "score": {
    "total": 78,
    "level": "high",
    "reasons": [
      "Abuse confidence score is 72",
      "18 abuse reports",
      "Recently reported"
    ]
  },
  "reputation": {
    "abuseipdb": {
      "confidence_score": 72,
      "total_reports": 18
    }
  }
}

Exit codes

0 – Success

1 – Invalid input

2 – Configuration error (missing API key)

3 – Provider/API error

Roadmap

Domain enrichment

Additional providers (VirusTotal, Shodan)

Local caching

API mode

Dashboard UI

Disclaimer

This tool relies on third-party threat intelligence sources.
Results should be used as signals, not absolute truth.

License

MIT
