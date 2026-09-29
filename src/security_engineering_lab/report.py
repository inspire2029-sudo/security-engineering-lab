from __future__ import annotations

from dataclasses import dataclass

from .headers import HeaderCheck, inspect_headers, validate_url
from .tls import TLSCertificate, inspect_certificate


@dataclass(frozen=True)
class SiteSecurityReport:
    url: str
    headers: list[HeaderCheck]
    certificate: TLSCertificate | None


def inspect_site(url: str, timeout: float = 10.0) -> SiteSecurityReport:
    validate_url(url)

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    headers = inspect_headers(url, timeout=timeout)
    certificate = inspect_certificate(url, timeout=timeout) if url.startswith("https://") else None

    return SiteSecurityReport(
        url=url,
        headers=headers,
        certificate=certificate,
    )
