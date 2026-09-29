from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse


@dataclass(frozen=True)
class TLSCertificate:
    hostname: str
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    days_remaining: int


def _name_to_string(name: tuple[tuple[tuple[str, str], ...], ...]) -> str:
    parts = []
    for section in name:
        for key, value in section:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def validate_https_url(url: str) -> tuple[str, int]:
    parsed = urlparse(url)

    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("URL must use https and include a hostname")

    port = parsed.port or 443
    return parsed.hostname, port


def inspect_certificate(url: str, timeout: float = 10.0) -> TLSCertificate:
    hostname, port = validate_https_url(url)

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                certificate = tls_sock.getpeercert()
    except (OSError, ssl.SSLError) as exc:
        raise RuntimeError(f"TLS connection failed: {exc}") from exc

    try:
        not_before = datetime.strptime(
            certificate["notBefore"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(
            certificate["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
    except (KeyError, ValueError) as exc:
        raise RuntimeError("TLS certificate has an invalid validity period") from exc

    days_remaining = (not_after - datetime.now(timezone.utc)).days

    return TLSCertificate(
        hostname=hostname,
        subject=_name_to_string(certificate.get("subject", ())),
        issuer=_name_to_string(certificate.get("issuer", ())),
        serial_number=certificate.get("serialNumber", ""),
        not_before=not_before,
        not_after=not_after,
        days_remaining=days_remaining,
    )
