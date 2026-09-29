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

    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
    )
    response.raise_for_status()

    headers = response.headers

    return [
        HeaderCheck(
            name=name,
            present=name in headers,
            value=headers.get(name),
        )
        for name in RECOMMENDED_HEADERS
    ]
