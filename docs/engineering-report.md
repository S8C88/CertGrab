# Engineering Report: CertGrab v1.0

## Overview

**CertGrab** is a TLS/SSL certificate grabber and vulnerability checker built
with zero external dependencies, leveraging Python 3.14's new `ssl.Certificate`
API for native X.509 parsing.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    certgrab.py                       │
├─────────────────────────────────────────────────────┤
│ grab_certificate_chain()                             │
│   ├─ socket.create_connection()                      │
│   ├─ ssl.SSLContext.wrap_socket()                    │
│   ├─ ssl.SSLObject.get_peer_cert_chain()             │
│   └─ parse_ssl_cert()  ← for each cert               │
├─────────────────────────────────────────────────────┤
│ parse_ssl_cert(cert: ssl.Certificate) → dict         │
│   ├─ cert.subject / issuer / serial_number           │
│   ├─ cert.not_valid_before_utc / _after_utc          │
│   ├─ cert.fingerprint("sha256") / ("sha1")           │
│   ├─ cert.public_key().key_type / .key_size          │
│   └─ cert.subject_alt_names                          │
├─────────────────────────────────────────────────────┤
│ Vulnerability checks:                                │
│   ├─ check_heartbleed()  — raw TLS heartbeat probe   │
│   ├─ check_poodle()      — SSLv3 fallback test       │
│   └─ check_insecure_ciphers() — weak cipher scan     │
└─────────────────────────────────────────────────────┘
```

## Key Design Decisions

### Zero external dependencies
- Uses Python 3.14's new `ssl.Certificate` class for all X.509 field parsing
- Eliminates need for `cryptography`, `pyopenssl`, or any third-party lib
- Only stdlib used: `ssl`, `socket`, `hashlib`, `argparse`, `datetime`

### Mock-friendly test architecture
- All vulnerability checks use raw sockets, making them trivially mockable
- Certificate parsing operates on mock objects (MagicMock with property stubs)
- No network calls in test suite — safe for CI/offline environments

### Raw TLS heartbeat probe
- Heartbleed check uses hand-crafted TLS record layer bytes
- Builds ClientHello → parses ServerHello → sends oversized HeartbeatRequest
- Compares response size to detect memory leak

### Vulnerability check philosophy
- **Heartbleed**: High-confidence if response >> request; medium if any response;
  low if timeout (server patched)
- **POODLE**: Binary check — SSLv3 accepted = vulnerable with high confidence
- **Weak ciphers**: Matches negotiated cipher name against known-weak keywords

## File Layout

```
18-CertGrab/
├── certgrab.py              # Main grabber + vulnerability checks
├── tests/
│   └── test_certgrab.py     # 21 test functions, all mocked
├── docs/
│   └── engineering-report.md
├── README.md
├── LICENSE
├── requirements.txt
└── .gitignore
```

## Test Coverage

21 test functions covering:

| Test | What it validates |
|------|-------------------|
| `test_version` | Correct version string |
| `test_parse_ssl_cert_subject` | Subject parsing from mock cert |
| `test_parse_ssl_cert_issuer` | Issuer parsing |
| `test_parse_ssl_cert_serial` | Serial number extraction |
| `test_parse_ssl_cert_validity_days` | Validity period calculation |
| `test_parse_ssl_cert_sans` | SAN extraction |
| `test_parse_ssl_cert_fingerprints` | SHA-256 and SHA-1 lengths |
| `test_parse_ssl_cert_public_key` | Key type and size |
| `test_parse_ssl_cert_version` | X.509 version field |
| `test_check_heartbleed_not_vulnerable` | Normal heartbeat response |
| `test_check_heartbleed_vulnerable` | Oversized heartbeat response |
| `test_check_heartbleed_timeout` | Heartbeat timeout handling |
| `test_check_poodle_vulnerable` | SSLv3 accepted |
| `test_check_poodle_not_vulnerable` | SSLv3 rejected |
| `test_check_insecure_ciphers_none` | No weak ciphers |
| `test_check_insecure_ciphers_weak` | Weak cipher (RC4) detected |
| `test_grab_certificate_chain` | Full chain grab (2 certs) |
| `test_get_fingerprint` | PEM fingerprint computation |
| `test_cli_help` | CLI parser help |
| `test_build_client_hello` | Raw TLS ClientHello structure |
| `test_build_heartbeat_request` | Raw TLS Heartbeat structure |

## Future Improvements

- Add OCSP stapling check
- Certificate transparency log verification
- TLS 1.3 early data (0-RTT) check
- Export as JSON/CSV for toolchain integration
- Add `--sni` flag for custom SNI hostname
- Wildcard cert matching analysis

---

*Report generated for CertGrab v1.0 — MIT © 2026 S8C88*
