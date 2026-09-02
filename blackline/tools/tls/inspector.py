"""TLS handshake and certificate inspection using Python ssl and OpenSSL."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import socket
import ssl
import tempfile
import time
from pathlib import Path

from blackline.utils.exec import run_command


@dataclass(frozen=True, slots=True)
class TlsInspectionResult:
    """Structured facts observed from one TLS endpoint."""

    ok: bool
    host: str
    port: int
    subject: str = ""
    issuer: str = ""
    sans: tuple[str, ...] = field(default_factory=tuple)
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: int | None = None
    protocol: str = ""
    cipher: str = ""
    certificate_sha256: str = ""
    provider: str = "python ssl"
    certificate_parser: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)
    raw_output: str = ""
    error: str = ""
    elapsed_seconds: float = 0.0


def inspect_tls(
    host: str,
    *,
    port: int = 443,
    server_name: str = "",
    timeout_seconds: float = 10.0,
) -> TlsInspectionResult:
    """Inspect an endpoint without requiring its certificate to be trusted locally.

    Python's TLS stack owns the connection, negotiated protocol, and cipher. OpenSSL
    decodes the returned certificate into portable subject/SAN/validity fields.
    """
    host = host.strip()
    started = time.perf_counter()
    if not host:
        return TlsInspectionResult(False, host, port, error="missing TLS host")
    if not 1 <= port <= 65535:
        return TlsInspectionResult(False, host, port, error="invalid TLS port")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as connection:
            with context.wrap_socket(connection, server_hostname=server_name or None) as tls_socket:
                certificate_der = tls_socket.getpeercert(binary_form=True)
                cipher_info = tls_socket.cipher()
                protocol = tls_socket.version() or ""
    except (OSError, ssl.SSLError) as exc:
        return TlsInspectionResult(
            False,
            host,
            port,
            error=str(exc),
            elapsed_seconds=time.perf_counter() - started,
        )

    cipher = cipher_info[0] if cipher_info else ""
    certificate_sha256 = hashlib.sha256(certificate_der).hexdigest() if certificate_der else ""
    metadata, parser_warning, raw_output = _decode_certificate_with_openssl(certificate_der, timeout_seconds)
    warnings = (parser_warning,) if parser_warning else ()
    return TlsInspectionResult(
        True,
        host,
        port,
        subject=metadata["subject"],
        issuer=metadata["issuer"],
        sans=metadata["sans"],
        not_before=metadata["not_before"],
        not_after=metadata["not_after"],
        days_until_expiry=_days_until(metadata["not_after"]),
        protocol=protocol,
        cipher=cipher,
        certificate_sha256=certificate_sha256,
        certificate_parser="openssl" if not parser_warning else "",
        warnings=warnings,
        raw_output=raw_output,
        elapsed_seconds=time.perf_counter() - started,
    )


def parse_openssl_certificate_output(output: str) -> dict[str, object]:
    """Parse the deliberately small, stable subset emitted by ``openssl x509``."""
    metadata: dict[str, object] = {
        "subject": "",
        "issuer": "",
        "sans": (),
        "not_before": "",
        "not_after": "",
    }
    san_values: list[str] = []
    in_san_extension = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("subject="):
            metadata["subject"] = line.removeprefix("subject=").strip()
            in_san_extension = False
        elif line.startswith("issuer="):
            metadata["issuer"] = line.removeprefix("issuer=").strip()
            in_san_extension = False
        elif line.startswith("notBefore="):
            metadata["not_before"] = _normalize_openssl_date(line.removeprefix("notBefore=").strip())
            in_san_extension = False
        elif line.startswith("notAfter="):
            metadata["not_after"] = _normalize_openssl_date(line.removeprefix("notAfter=").strip())
            in_san_extension = False
        elif "Subject Alternative Name" in line:
            in_san_extension = True
        elif in_san_extension and line:
            san_values.extend(value.strip() for value in line.split(",") if value.strip())
            in_san_extension = False
    metadata["sans"] = tuple(san_values)
    return metadata


def _decode_certificate_with_openssl(certificate_der: bytes, timeout_seconds: float) -> tuple[dict[str, object], str, str]:
    empty = {"subject": "", "issuer": "", "sans": (), "not_before": "", "not_after": ""}
    if not certificate_der:
        return empty, "server did not provide a certificate", ""

    certificate_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False, encoding="ascii") as temporary_file:
            certificate_path = Path(temporary_file.name)
            temporary_file.write(ssl.DER_cert_to_PEM_cert(certificate_der))
        result = run_command(
            ("openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName", "-in", str(certificate_path)),
            timeout=timeout_seconds,
        )
        if not result.ok:
            return empty, f"OpenSSL certificate parsing unavailable: {result.stderr.strip() or 'failed'}", result.stdout
        return parse_openssl_certificate_output(result.stdout), "", result.stdout
    except OSError as exc:
        return empty, f"OpenSSL certificate parsing unavailable: {exc}", ""
    finally:
        if certificate_path is not None:
            certificate_path.unlink(missing_ok=True)


def _normalize_openssl_date(value: str) -> str:
    """Convert OpenSSL's GMT date to an ISO 8601 timestamp when possible."""
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC).isoformat()
    except ValueError:
        return value


def _days_until(value: str) -> int | None:
    try:
        expiry = datetime.fromisoformat(value)
    except ValueError:
        return None
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    return (expiry - datetime.now(UTC)).days
