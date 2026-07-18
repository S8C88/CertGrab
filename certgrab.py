#!/usr/bin/env python3
"""
CertGrab — TLS/SSL certificate grabber and vulnerability checker.
Network engineer style. Connects to a target, grabs the full certificate
chain, parses X.509 fields, and optionally checks for known vulnerabilities.

Zero external dependencies — uses Python 3.14+ ssl.Certificate API.

Author: S8C88 (MIT License 2026)
"""

import argparse
import hashlib
import socket
import ssl
import sys

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INSECURE_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "aNULL",
    "ADH", "LOW", "MEDIUM", "CBC",
]


# ---------------------------------------------------------------------------
# Certificate grabbing
# ---------------------------------------------------------------------------

def grab_certificate_chain(target: str, port: int = 443,
                           timeout: float = 10.0) -> list[dict]:
    """Connect via TLS and retrieve the full certificate chain."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    raw_sock = socket.create_connection((target, port), timeout=timeout)
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=target)
    tls_sock.settimeout(timeout)

    chain = tls_sock.get_peer_cert_chain()
    result = [parse_ssl_cert(cert) for cert in chain]
    tls_sock.close()
    return result


def parse_ssl_cert(cert) -> dict:
    """Parse an ssl.Certificate into a structured dict (Python 3.14+)."""
    info = {
        "subject":        str(cert.subject),
        "issuer":         str(cert.issuer),
        "serial_number":  str(cert.serial_number),
        "version":        cert.version,
        "not_before":     cert.not_valid_before_utc.isoformat(),
        "not_after":      cert.not_valid_after_utc.isoformat(),
        "validity_days":  (cert.not_valid_after_utc
                           - cert.not_valid_before_utc).days,
        "sans":           _extract_sans(cert),
        "signature_algorithm": _sig_alg(cert),
        "fingerprint_sha256":  cert.fingerprint("sha256").hex(),
        "fingerprint_sha1":    cert.fingerprint("sha1").hex(),
        "public_key_type":     cert.public_key().key_type,
        "public_key_size":     cert.public_key().key_size,
    }
    return info


def _extract_sans(cert) -> list[str]:
    """Pull SAN entries from a certificate."""
    try:
        return [f"{t}:{v}" for t, v in cert.subject_alt_names]
    except (AttributeError, TypeError):
        return []


def _sig_alg(cert) -> str:
    """Return signature algorithm name."""
    try:
        return cert.signature_algorithm or "unknown"
    except AttributeError:
        return "unknown"


def get_fingerprint(cert_pem: str) -> dict:
    """Compute SHA-1 and SHA-256 fingerprints from a PEM string."""
    cert = ssl.PEM_cert_to_DER_cert(cert_pem)
    return {
        "sha1":   hashlib.sha1(cert).hexdigest(),
        "sha256": hashlib.sha256(cert).hexdigest(),
    }


# ---------------------------------------------------------------------------
# Vulnerability checks
# ---------------------------------------------------------------------------

def check_heartbleed(target: str, port: int = 443,
                     timeout: float = 10.0) -> dict:
    """
    Check for Heartbleed (CVE-2014-0160) by sending a malformed TLS
    heartbeat request. Vulnerable servers may echo back extra memory.
    """
    result = {"vulnerable": False, "confidence": "low", "detail": ""}

    try:
        raw = socket.create_connection((target, port), timeout=timeout)
        raw.settimeout(timeout)

        # Send a minimal TLS ClientHello
        raw.sendall(_build_client_hello())
        _ = raw.recv(4096)  # consume ServerHello

        # Send oversized heartbeat request
        hb_req = _build_heartbeat_request(payload_size=0x4000)
        raw.sendall(hb_req)

        try:
            hb_resp = raw.recv(65536)
            if len(hb_resp) > len(hb_req) + 100:
                result["vulnerable"] = True
                result["confidence"] = "high"
                result["detail"] = (f"Response ({len(hb_resp)}B) >> request "
                                    f"({len(hb_req)}B) — memory leak detected")
            elif len(hb_resp) > 0:
                result["detail"] = "Heartbeat response normal size"
                result["confidence"] = "medium"
        except socket.timeout:
            result["detail"] = "No heartbeat response (server patched)"
            result["confidence"] = "high"
        raw.close()
    except Exception as e:
        result["detail"] = f"Check failed: {e}"

    return result


def check_poodle(target: str, port: int = 443, timeout: float = 10.0) -> dict:
    """
    Check for POODLE (CVE-2014-3566) by sending a raw SSLv3 ClientHello
    and checking if the server responds with SSLv3 ServerHello.
    """
    result = {"vulnerable": False, "confidence": "low", "detail": ""}

    try:
        raw = socket.create_connection((target, port), timeout=timeout)
        raw.settimeout(timeout)

        # Send raw SSLv3 ClientHello
        sslv3_hello = _build_sslv3_client_hello()
        raw.sendall(sslv3_hello)

        try:
            resp = raw.recv(4096)
            # Check if response starts with SSLv3 record (content type + 0x03,0x00)
            if len(resp) >= 3 and resp[1] == 0x03 and resp[2] == 0x00:
                result["vulnerable"] = True
                result["confidence"] = "high"
                result["detail"] = "Server responded with SSLv3 ServerHello — POODLE vulnerable"
            elif len(resp) >= 3:
                result["detail"] = (f"Server responded with TLS "
                                    f"{resp[1]}.{resp[2]} (safe)")
                result["confidence"] = "medium"
            else:
                result["detail"] = "Response too short to determine protocol"
        except socket.timeout:
            result["detail"] = "No response to SSLv3 ClientHello (safe)"
            result["confidence"] = "medium"
        raw.close()
    except Exception as e:
        result["detail"] = f"Check failed: {e}"

    return result


def check_insecure_ciphers(target: str, port: int = 443,
                           timeout: float = 10.0) -> dict:
    """
    Probe for insecure cipher suites.
    """
    result = {"insecure_ciphers": [], "detail": ""}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:eNULL")

        raw = socket.create_connection((target, port), timeout=timeout)
        tls = ctx.wrap_socket(raw, server_hostname=target)
        tls.settimeout(timeout)

        negotiated = tls.cipher()
        if negotiated:
            cname, ver, bits = negotiated
            for weak in INSECURE_CIPHERS:
                if weak.lower() in cname.lower():
                    result["insecure_ciphers"].append({
                        "cipher": cname, "tls_version": ver,
                        "bits": bits, "reason": f"Contains {weak}"})
            result["detail"] = (f"Negotiated: {cname} (TLS {ver}, {bits}b)")
        tls.close()
    except Exception as e:
        result["detail"] = f"Check failed: {e}"

    return result


# ---------------------------------------------------------------------------
# Raw TLS helpers
# ---------------------------------------------------------------------------

def _build_client_hello() -> bytes:
    """Minimal TLS 1.2 ClientHello."""
    body = bytes([0x01])         # HandshakeType client_hello
    body += bytes([0x00, 0x00, 0x2f])  # length placeholder
    body += bytes([0x03, 0x03])  # TLS 1.2
    body += b'\x00' * 32         # random
    body += b'\x00'              # session ID length
    body += bytes([0x00, 0x02])  # cipher suites length
    body += bytes([0xc0, 0x2f])  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    body += b'\x01\x00'          # compression methods (null)
    body += bytes([0x00, 0x00])  # extensions length

    # Patch handshake length
    hs_len = len(body) - 4
    body = body[:2] + hs_len.to_bytes(3, 'big') + body[5:]

    record = bytes([0x16, 0x03, 0x01])  # Handshake, TLS 1.0 record
    record += len(body).to_bytes(2, 'big')
    record += body
    return record


def _build_sslv3_client_hello() -> bytes:
    """Build SSLv3 ClientHello for POODLE probing."""
    body = bytes([0x01])         # HandshakeType client_hello
    body += bytes([0x00, 0x00, 0x2d])  # length placeholder
    body += bytes([0x03, 0x00])  # SSLv3
    body += b'\x00' * 32         # random
    body += b'\x00'              # session ID length
    body += bytes([0x00, 0x04])  # cipher suites length
    # Include some SSLv3 CBC ciphers (POODLE-relevant)
    body += bytes([0x00, 0x0a])  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    body += bytes([0x00, 0x2f])  # TLS_RSA_WITH_AES_128_CBC_SHA
    body += b'\x01\x00'          # compression methods (null)

    hs_len = len(body) - 4
    body = body[:2] + hs_len.to_bytes(3, 'big') + body[5:]

    record = bytes([0x16, 0x03, 0x00])  # Handshake, SSLv3 record
    record += len(body).to_bytes(2, 'big')
    record += body
    return record


def _build_heartbeat_request(payload_size: int = 3) -> bytes:
    """Build a TLS HeartbeatRequest with given payload size."""
    payload = b'A' * payload_size
    hb_type = 0x01  # heartbeat_request
    padding = b'\x00' * 16

    body = bytes([hb_type])
    body += len(payload).to_bytes(2, 'big')
    body += payload
    body += padding

    record = bytes([0x18, 0x03, 0x03])  # Heartbeat, TLS 1.2 record
    record += len(body).to_bytes(2, 'big')
    record += body
    return record


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cli():
    parser = argparse.ArgumentParser(
        description=f"CertGrab v{__version__} — TLS/SSL certificate grabber "
                    f"and vulnerability checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  certgrab.py -t example.com
  certgrab.py -t example.com -p 8443
  certgrab.py -t example.com --check-vulns
  certgrab.py -t 10.0.0.1 -p 443 --check-vulns
        """)
    parser.add_argument("-t", "--target", required=True,
                        help="Target hostname or IP")
    parser.add_argument("-p", "--port", type=int, default=443,
                        help="Target port (default: 443)")
    parser.add_argument("--check-vulns", action="store_true",
                        help="Check Heartbleed, POODLE, weak ciphers")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Connection timeout (default: 10)")
    parser.add_argument("--version", action="version",
                        version=f"CertGrab v{__version__}")
    args = parser.parse_args()

    print(f"[*] Connecting to {args.target}:{args.port} ...")
    try:
        chain = grab_certificate_chain(args.target, args.port, args.timeout)
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        sys.exit(1)

    print(f"[+] Chain: {len(chain)} certificate(s)\n")

    for i, cert in enumerate(chain, 1):
        print(f"--- Certificate #{i} ---")
        print(f"  Subject:            {cert['subject']}")
        print(f"  Issuer:             {cert['issuer']}")
        print(f"  Serial:             {cert['serial_number']}")
        print(f"  Version:            {cert['version']}")
        print(f"  Valid from:         {cert['not_before']}")
        print(f"  Valid until:        {cert['not_after']}")
        print(f"  Validity period:    {cert['validity_days']} days")
        print(f"  Signature alg:      {cert['signature_algorithm']}")
        print(f"  Public key:         {cert['public_key_type']} "
              f"({cert['public_key_size']} bits)")
        print(f"  SHA-256 fingerprint:{cert['fingerprint_sha256']}")
        print(f"  SHA-1 fingerprint:  {cert['fingerprint_sha1']}")
        if cert['sans']:
            print(f"  SANs ({len(cert['sans'])}):")
            for san in cert['sans'][:10]:
                print(f"    - {san}")
            if len(cert['sans']) > 10:
                print(f"    ... and {len(cert['sans']) - 10} more")
        print()

    if args.check_vulns:
        print("=== Vulnerability Checks ===\n")

        print("[*] Heartbleed (CVE-2014-0160)...")
        r = check_heartbleed(args.target, args.port, args.timeout)
        print(f"  [{'VULN' if r['vulnerable'] else 'OK'}] {r['detail']}")

        print("[*] POODLE (CVE-2014-3566)...")
        r = check_poodle(args.target, args.port, args.timeout)
        print(f"  [{'VULN' if r['vulnerable'] else 'OK'}] {r['detail']}")

        print("[*] Insecure cipher suites...")
        r = check_insecure_ciphers(args.target, args.port, args.timeout)
        if r["insecure_ciphers"]:
            for c in r["insecure_ciphers"]:
                print(f"  [WEAK] {c['cipher']} ({c['reason']})")
        else:
            print(f"  [OK] {r['detail']}")


if __name__ == "__main__":
    cli()
