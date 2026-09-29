from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import requests


@dataclass(frozen=True)
class HeaderCheck:
    name: str
    present: bool
    value: str | None


RECOMMENDED_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def validate_url(url: str) -> str:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must include an http or https scheme")

    return url


def inspect_headers(url: str, timeout: float = 10.0) -> list[HeaderCheck]:
    validate_url(url)

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"HTTP request failed: {exc}") from exc

    return [
        HeaderCheck(
            name=name,
            present=name in response.headers,
            value=response.headers.get(name),
        )
        for name in RECOMMENDED_HEADERS
    ]
