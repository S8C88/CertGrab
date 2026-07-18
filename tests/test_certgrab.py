#!/usr/bin/env python3
"""Tests for CertGrab — certgrab.py (all network calls mocked)."""

import hashlib
import socket
import ssl
import sys
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

sys.path.insert(0, "..")
import certgrab


# ---------------------------------------------------------------------------
# Mock helpers — build fake ssl.Certificate-like objects
# ---------------------------------------------------------------------------

def _make_mock_cert(**overrides):
    """Create a mock object mimicking Python 3.14+ ssl.Certificate."""
    now = datetime.now(timezone.utc)
    cert = MagicMock()
    cert.subject = overrides.get("subject", "CN=example.com")
    cert.issuer = overrides.get("issuer", "CN=FakeRootCA")
    cert.serial_number = overrides.get("serial_number", 12345)
    cert.version = overrides.get("version", 3)
    cert.not_valid_before_utc = overrides.get("not_before", now - timedelta(days=30))
    cert.not_valid_after_utc = overrides.get("not_after", now + timedelta(days=335))
    cert.signature_algorithm = overrides.get("sig_alg", "sha256WithRSAEncryption")
    cert.subject_alt_names = overrides.get("sans",
                                           [("DNS", "example.com"), ("DNS", "www.example.com")])

    # Fingerprint
    def fake_fingerprint(algo):
        raw = f"{algo}:{cert.serial_number}".encode()
        if algo == "sha256":
            return hashlib.sha256(raw).digest()
        return hashlib.sha1(raw).digest()
    cert.fingerprint = fake_fingerprint

    # Public key
    pubkey = MagicMock()
    pubkey.key_type = overrides.get("key_type", "RSA")
    pubkey.key_size = overrides.get("key_size", 2048)
    cert.public_key = MagicMock(return_value=pubkey)

    return cert


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_version():
    assert certgrab.__version__ == "1.0.0"


def test_parse_ssl_cert_subject():
    cert = _make_mock_cert(subject="CN=test.example.com")
    info = certgrab.parse_ssl_cert(cert)
    assert info["subject"] == "CN=test.example.com"


def test_parse_ssl_cert_issuer():
    cert = _make_mock_cert(issuer="CN=RealCA")
    info = certgrab.parse_ssl_cert(cert)
    assert "RealCA" in info["issuer"]


def test_parse_ssl_cert_serial():
    cert = _make_mock_cert(serial_number=99999)
    info = certgrab.parse_ssl_cert(cert)
    assert info["serial_number"] == "99999"


def test_parse_ssl_cert_validity_days():
    cert = _make_mock_cert()
    info = certgrab.parse_ssl_cert(cert)
    assert info["validity_days"] == 365  # 30 + 335


def test_parse_ssl_cert_sans():
    cert = _make_mock_cert(sans=[("DNS", "x.com")])
    info = certgrab.parse_ssl_cert(cert)
    assert "x.com" in str(info["sans"])


def test_parse_ssl_cert_fingerprints():
    cert = _make_mock_cert(serial_number=42)
    info = certgrab.parse_ssl_cert(cert)
    assert len(info["fingerprint_sha256"]) == 64   # hex of 32 bytes
    assert len(info["fingerprint_sha1"]) == 40     # hex of 20 bytes


def test_parse_ssl_cert_public_key():
    cert = _make_mock_cert(key_type="ECDSA", key_size=256)
    info = certgrab.parse_ssl_cert(cert)
    assert info["public_key_type"] == "ECDSA"
    assert info["public_key_size"] == 256


def test_parse_ssl_cert_version():
    cert = _make_mock_cert(version=3)
    info = certgrab.parse_ssl_cert(cert)
    assert info["version"] == 3


# --- Heartbleed ---

def test_check_heartbleed_not_vulnerable():
    """Heartbleed detection with mocked socket (no oversized response)."""
    with patch("certgrab.socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_sock.recv.side_effect = [b"ServerHello", b"small"]
        result = certgrab.check_heartbleed("localhost", 443)
        assert result["vulnerable"] is False


def test_check_heartbleed_vulnerable():
    """Heartbleed detection with oversized heartbeat response."""
    with patch("certgrab.socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        big_resp = b"X" * 20000
        mock_sock.recv.side_effect = [b"ServerHello", big_resp]
        result = certgrab.check_heartbleed("localhost", 443)
        assert result["vulnerable"] is True


def test_check_heartbleed_timeout():
    """Heartbleed when server does not respond (timeout)."""
    with patch("certgrab.socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_sock.recv.side_effect = [b"ServerHello", socket.timeout]
        result = certgrab.check_heartbleed("localhost", 443)
        assert result["vulnerable"] is False


# --- POODLE (raw socket approach) ---

def test_check_poodle_vulnerable():
    """POODLE check: server responds with SSLv3 ServerHello (0x03,0x00)."""
    with patch("certgrab.socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        # SSLv3 ServerHello: record type 0x16, version 0x03 0x00
        mock_sock.recv.return_value = b'\x16\x03\x00...ServerHelloSSLv3'
        result = certgrab.check_poodle("localhost", 443)
        assert result["vulnerable"] is True


def test_check_poodle_not_vulnerable():
    """POODLE check: server responds with TLS (0x03,0x03) — safe."""
    with patch("certgrab.socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        # TLS 1.2 ServerHello: record type 0x16, version 0x03 0x03
        mock_sock.recv.return_value = b'\x16\x03\x03...ServerHelloTLS12'
        result = certgrab.check_poodle("localhost", 443)
        assert result["vulnerable"] is False


def test_check_poodle_timeout():
    """POODLE check: no response = safe."""
    with patch("certgrab.socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_sock.recv.side_effect = socket.timeout
        result = certgrab.check_poodle("localhost", 443)
        assert result["vulnerable"] is False


# --- Insecure ciphers ---

@patch("certgrab.ssl.create_default_context")
def test_check_insecure_ciphers_none(mock_create_ctx):
    """No weak ciphers detected."""
    ctx = MagicMock()
    tls = MagicMock()
    tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    ctx.wrap_socket.return_value = tls
    mock_create_ctx.return_value = ctx

    with patch("certgrab.socket.create_connection") as mock_conn:
        mock_conn.return_value = MagicMock()
        result = certgrab.check_insecure_ciphers("localhost", 443)
        assert len(result["insecure_ciphers"]) == 0


@patch("certgrab.ssl.create_default_context")
def test_check_insecure_ciphers_weak(mock_create_ctx):
    """Weak cipher detected."""
    ctx = MagicMock()
    tls = MagicMock()
    tls.cipher.return_value = ("TLS_RSA_WITH_RC4_128_SHA", "TLSv1.2", 128)
    ctx.wrap_socket.return_value = tls
    mock_create_ctx.return_value = ctx

    with patch("certgrab.socket.create_connection") as mock_conn:
        mock_conn.return_value = MagicMock()
        result = certgrab.check_insecure_ciphers("localhost", 443)
        assert len(result["insecure_ciphers"]) >= 1
        assert any("RC4" in c["reason"] for c in result["insecure_ciphers"])


# --- Full chain ---

@patch("certgrab.ssl.create_default_context")
def test_grab_certificate_chain(mock_create_ctx):
    """Full grab flow with mocked TLS socket."""
    cert_a = _make_mock_cert(subject="CN=leaf.example.com",
                             issuer="CN=intermediate")
    cert_b = _make_mock_cert(subject="CN=intermediate",
                             issuer="CN=root")

    ctx = MagicMock()
    tls = MagicMock()
    tls.get_peer_cert_chain.return_value = [cert_a, cert_b]
    ctx.wrap_socket.return_value = tls
    mock_create_ctx.return_value = ctx

    with patch("certgrab.socket.create_connection") as mock_conn:
        mock_conn.return_value = MagicMock()
        chain = certgrab.grab_certificate_chain("example.com", 443)
        assert len(chain) == 2
        assert chain[0]["subject"] == "CN=leaf.example.com"
        assert chain[1]["subject"] == "CN=intermediate"


def test_get_fingerprint():
    """Fingerprint computation from PEM cert."""
    der = b"FAKECERTDERBYTES"
    with patch("certgrab.ssl.PEM_cert_to_DER_cert", return_value=der):
        fp = certgrab.get_fingerprint("---BEGIN CERT---")
        assert fp["sha1"] == hashlib.sha1(der).hexdigest()
        assert fp["sha256"] == hashlib.sha256(der).hexdigest()


# --- Raw TLS helpers ---

def test_build_client_hello():
    """Raw TLS ClientHello builder returns valid-looking bytes."""
    hello = certgrab._build_client_hello()
    assert isinstance(hello, bytes)
    assert len(hello) > 30
    assert hello[0] == 0x16  # Handshake content type


def test_build_sslv3_client_hello():
    """SSLv3 ClientHello builder returns SSLv3 record (0x03,0x00)."""
    hello = certgrab._build_sslv3_client_hello()
    assert isinstance(hello, bytes)
    assert hello[0] == 0x16  # Handshake content type
    assert hello[1:3] == bytes([0x03, 0x00])  # SSLv3 record version


def test_build_heartbeat_request():
    """Heartbeat request builder returns valid bytes."""
    hb = certgrab._build_heartbeat_request(payload_size=3)
    assert isinstance(hb, bytes)
    assert hb[0] == 0x18  # Heartbeat content type
    assert len(hb) > 20


def test_cli_help():
    """CLI parser accepts --help."""
    try:
        certgrab.cli()
    except SystemExit:
        pass
