# CertGrab

![License](https://img.shields.io/badge/license-MIT-blue.svg)

**TLS/SSL certificate grabber and vulnerability checker** — network engineer
style. Connects to any TLS-enabled service, retrieves the full certificate
chain, parses X.509 fields, and optionally checks for Heartbleed, POODLE,
and insecure cipher suites.

## Features

- 🔍 **Full chain grab** — retrieves and parses every cert in the chain
- 📋 **Rich output** — subject, issuer, SANs, validity, fingerprints, key type
- 🛡️ **Vulnerability scanning** — Heartbleed (CVE-2014-0160), POODLE (CVE-2014-3566), weak ciphers
- ⚡ **Zero external deps** — uses Python 3.14+ `ssl.Certificate` API
- 🧪 **All tests mocked** — safe to run anywhere, no real hosts contacted

## Quick Start

```bash
# Grab certificate from a host
python3 certgrab.py -t example.com

# Custom port
python3 certgrab.py -t example.com -p 8443

# Run vulnerability checks
python3 certgrab.py -t example.com --check-vulns

# Increase timeout for slow connections
python3 certgrab.py -t 10.0.0.1 -p 443 --check-vulns --timeout 15
```

## Usage

```text
usage: certgrab.py [-h] -t TARGET [-p PORT] [--check-vulns] [--timeout TIMEOUT] [--version]

CertGrab v1.0 — TLS/SSL certificate grabber and vulnerability checker

options:
  -h, --help        show this help message and exit
  -t, --target      Target hostname or IP address
  -p, --port        Target port (default: 443)
  --check-vulns     Check Heartbleed, POODLE, weak ciphers
  --timeout         Connection timeout in seconds (default: 10)
  --version         show program's version and exit
```

## Architecture

```mermaid
graph TD
    A[CLI: -t target -p port] --> B{grab_certificate_chain}
    B --> C[Socket connect]
    C --> D[TLS handshake]
    D --> E[get_peer_cert_chain]
    E --> F[parse_ssl_cert x N]
    F --> G[Formatted output]
    A -->|--check-vulns| H[check_heartbleed]
    A -->|--check-vulns| I[check_poodle]
    A -->|--check-vulns| J[check_insecure_ciphers]
    H --> G
    I --> G
    J --> G
```

### Certificate Parsing Flow

```mermaid
sequenceDiagram
    participant CLI
    participant Grabber
    participant Socket
    participant TLS
    participant Parser
    CLI->>Grabber: target, port, timeout
    Grabber->>Socket: create_connection
    Socket-->>Grabber: raw socket
    Grabber->>TLS: context.wrap_socket
    TLS-->>Grabber: tls_sock
    Grabber->>TLS: get_peer_cert_chain
    TLS-->>Grabber: [Cert, Cert, ...]
    loop for each cert
        Grabber->>Parser: parse_ssl_cert(cert)
        Parser-->>Grabber: {subject, issuer, sans, ...}
    end
    Grabber-->>CLI: [dict, dict, ...]
```

## Vulnerability Checks

| Check | CVE | Method |
|-------|-----|--------|
| Heartbleed | 2014-0160 | Sends oversized TLS heartbeat; checks response size |
| POODLE | 2014-3566 | Attempts SSLv3 connection; success = vulnerable |
| Weak ciphers | Various | Negotiates with weak cipher list; checks negotiated cipher |

## Testing

```bash
python3 -m pytest tests/ -v
```

All tests use mocked network calls — no real hosts are contacted.

## License

MIT © 2026 S8C88
