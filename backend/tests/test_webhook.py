import socket

import httpcore
import httpx
import pytest

from app.config import settings
from app.notifications.webhook import (
    WebhookDeliveryError,
    build_notification_payload,
    deliver_webhook,
    _PinnedIPNetworkBackend,
)


def _public_dns(_host, _port, type=None):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]


def test_webhook_payload_contains_summary_top_findings_and_ai_but_no_source_secrets():
    report = {
        "status": "completed",
        "findings": [{
            "rule_id": "hardcoded_secret",
            "severity": "HIGH",
            "path": "src/App.kt",
            "line": 12,
            "message": "Credential exposed",
            "masked_value": "ghp_****",
            "code_context": [{"line": 12, "text": "token = [REDACTED]"}],
            "recommendation": "Rotate credential",
            "cve": None,
        }],
        "explanations": [{
            "root_cause": "A credential is hardcoded.",
            "impact": "It may be reused by an attacker.",
            "recommendation": "Move it to a secret store.",
        }],
        "explained_count": 1,
    }

    payload = build_notification_payload(report)

    assert payload["summary"]["total_findings"] == 1
    assert payload["summary"]["severity"] == {"HIGH": 1}
    assert payload["top_findings"][0]["rule_id"] == "hardcoded_secret"
    assert "masked_value" not in payload["top_findings"][0]
    assert "code_context" not in payload["top_findings"][0]
    assert "hardcoded" in payload["ai_summary"][0]


def test_webhook_rejects_unlisted_host_and_private_dns(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "notify_webhook_allowed_hosts", "webhook.site")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
    ])

    with pytest.raises(WebhookDeliveryError, match="non-public IP"):
        deliver_webhook("https://webhook.site/abc", {"event": "test"})

    with pytest.raises(WebhookDeliveryError, match="NOTIFY_WEBHOOK_ALLOWED_HOSTS"):
        deliver_webhook("https://example.com/hook", {"event": "test"})


def test_webhook_posts_json_without_following_redirects(monkeypatch):
    monkeypatch.setattr(settings, "notify_webhook_allowed_hosts", "webhook.site")
    monkeypatch.setattr(socket, "getaddrinfo", _public_dns)
    calls = {}

    class FakeClient:
        def __init__(self, **kwargs):
            calls["client_options"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def post(self, url, json, headers):
            calls.update(url=url, payload=json, headers=headers)
            return httpx.Response(204, request=httpx.Request("POST", url))

    monkeypatch.setattr("app.notifications.webhook.httpx.Client", FakeClient)

    result = deliver_webhook("https://webhook.site/unique-id", {"event": "test"})

    assert result == {"http_status": 204, "delivered": True}
    assert calls["payload"] == {"event": "test"}
    assert calls["client_options"]["follow_redirects"] is False
    assert calls["client_options"]["trust_env"] is False
    transport = calls["client_options"]["transport"]
    assert transport._pool._ssl_context.check_hostname is True
    assert transport._pool._ssl_context.verify_mode != 0
    backend = transport._pool._network_backend
    assert isinstance(backend, _PinnedIPNetworkBackend)
    assert backend._hostname == "webhook.site"
    assert backend._addresses == ("8.8.8.8",)
    assert calls["url"] == "https://webhook.site/unique-id"


def test_webhook_rejects_redirect_response(monkeypatch):
    monkeypatch.setattr(settings, "notify_webhook_allowed_hosts", "webhook.site")
    monkeypatch.setattr(socket, "getaddrinfo", _public_dns)

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def post(self, url, json, headers):
            return httpx.Response(302, headers={"Location": "https://example.com"}, request=httpx.Request("POST", url))

    monkeypatch.setattr("app.notifications.webhook.httpx.Client", FakeClient)

    with pytest.raises(WebhookDeliveryError, match="redirect"):
        deliver_webhook("https://webhook.site/unique-id", {"event": "test"})


def test_webhook_payload_bounds_untrusted_finding_text():
    payload = build_notification_payload({
        "findings": [{
            "rule_id": "x" * 1000,
            "severity": "HIGH",
            "path": "p" * 2000,
            "message": "m" * 10000,
            "recommendation": "r" * 10000,
        }]
    })

    finding = payload["top_findings"][0]
    assert len(finding["rule_id"]) <= 120
    assert len(finding["path"]) <= 400
    assert len(finding["message"]) <= 600
    assert len(finding["recommendation"]) <= 800



def test_webhook_rejects_mixed_public_and_private_dns_before_connect(monkeypatch):
    monkeypatch.setattr(settings, "notify_webhook_allowed_hosts", "webhook.site")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
    ])

    def unexpected_client(**_kwargs):
        pytest.fail("HTTP client must not be created for mixed DNS answers")

    monkeypatch.setattr("app.notifications.webhook.httpx.Client", unexpected_client)

    with pytest.raises(WebhookDeliveryError, match="non-public IP"):
        deliver_webhook("https://webhook.site/hook", {"event": "test"})


def test_pinned_backend_uses_only_validated_ips_and_fails_over():
    class FakeBackend:
        def __init__(self):
            self.calls = []

        def connect_tcp(self, **kwargs):
            self.calls.append(kwargs)
            if len(self.calls) == 1:
                raise httpcore.ConnectError("simulated connection failure")
            return object()

    fake = FakeBackend()
    backend = _PinnedIPNetworkBackend(
        "webhook.site",
        ("8.8.8.8", "1.1.1.1"),
        backend=fake,
    )

    result = backend.connect_tcp(
        host=b"webhook.site",
        port=443,
        timeout=4.0,
        local_address=None,
        socket_options=None,
    )

    assert result is not None
    assert [call["host"] for call in fake.calls] == ["8.8.8.8", "1.1.1.1"]
    assert all(call["port"] == 443 for call in fake.calls)


@pytest.mark.parametrize(
    ("host", "port"),
    [
        (b"attacker.example", 443),
        (b"webhook.site", 80),
    ],
)
def test_pinned_backend_rejects_unexpected_destination(host, port):
    class FakeBackend:
        def connect_tcp(self, **_kwargs):
            pytest.fail("Unexpected destination must be rejected before TCP connect")

    backend = _PinnedIPNetworkBackend(
        "webhook.site",
        ("8.8.8.8",),
        backend=FakeBackend(),
    )

    with pytest.raises(httpcore.ConnectError, match="Unexpected webhook"):
        backend.connect_tcp(host=host, port=port)


def test_pinned_backend_does_not_retry_unvalidated_addresses():
    class FakeBackend:
        def __init__(self):
            self.calls = []

        def connect_tcp(self, **kwargs):
            self.calls.append(kwargs["host"])
            raise httpcore.ConnectError("simulated failure")

    fake = FakeBackend()
    backend = _PinnedIPNetworkBackend(
        "webhook.site",
        ("8.8.8.8", "1.1.1.1"),
        backend=fake,
    )

    with pytest.raises(httpcore.ConnectError, match="validated webhook IP"):
        backend.connect_tcp(host=b"webhook.site", port=443)

    assert fake.calls == ["8.8.8.8", "1.1.1.1"]


def _write_test_pem(server, cert_pem, key_pem):
    import tempfile
    from pathlib import Path

    directory = tempfile.TemporaryDirectory()
    server._test_cert_directory = directory
    cert_path = Path(directory.name) / "certificate.pem"
    key_path = Path(directory.name) / "key.pem"
    cert_path.write_text(cert_pem, encoding="ascii")
    key_path.write_text(key_pem, encoding="ascii")
    return str(cert_path), str(key_path)


def test_webhook_performs_tls_with_original_hostname_sni_and_certificate_validation(
    monkeypatch,
):
    import datetime
    import ssl
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "INVEST Test Root CA"),
    ])
    root_certificate = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "webhook.site"),
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("webhook.site")]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    root_cert_pem = root_certificate.public_bytes(
        serialization.Encoding.PEM
    ).decode()
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_path, key_path = _write_test_pem(server, cert_pem, key_pem)
    server_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = server_context.wrap_socket(server.socket, server_side=True)

    observed_sni = []

    def record_sni(_ssl_socket, server_name, _context):
        observed_sni.append(server_name)

    server_context.set_servername_callback(record_sni)

    monkeypatch.setattr(settings, "notify_webhook_allowed_hosts", "webhook.site")
    original_getaddrinfo = socket.getaddrinfo

    def resolve_test_webhook(host, *args, **kwargs):
        if host == "webhook.site":
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
            ]
        return original_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", resolve_test_webhook)

    original_connect_tcp = httpcore.SyncBackend.connect_tcp

    def connect_to_local_test_server(
        backend,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        if host == "8.8.8.8" and port == 443:
            host = "127.0.0.1"
            port = server.server_address[1]
        return original_connect_tcp(
            backend,
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    monkeypatch.setattr(
        httpcore.SyncBackend,
        "connect_tcp",
        connect_to_local_test_server,
    )

    original_transport_init = __import__(
        "app.notifications.webhook", fromlist=["_PinnedIPTransport"]
    )._PinnedIPTransport.__init__

    def transport_with_test_ca(transport, hostname, addresses):
        original_transport_init(transport, hostname, addresses)
        context = transport._pool._ssl_context
        context.load_verify_locations(cadata=root_cert_pem)
        root_der = x509.load_pem_x509_certificate(
            root_cert_pem.encode("ascii")
        ).public_bytes(serialization.Encoding.DER)
        trusted_certs = context.get_ca_certs(binary_form=True)
        assert root_der in trusted_certs, (
            "Test root CA was not added to the actual httpcore SSLContext; "
            f"store stats: {context.cert_store_stats()}"
        )

    monkeypatch.setattr(
        "app.notifications.webhook._PinnedIPTransport.__init__",
        transport_with_test_ca,
    )

    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        result = deliver_webhook(
            "https://webhook.site/test",
            {"event": "tls-check"},
        )
        assert result == {"http_status": 204, "delivered": True}
        assert observed_sni == ["webhook.site"]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
