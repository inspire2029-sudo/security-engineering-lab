from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .tls import TLSCertificate, inspect_certificate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect the TLS certificate presented by an HTTPS server."
    )
    parser.add_argument("url", help="HTTPS URL to inspect")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="TLS connection timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Print the certificate details as JSON.",
    )
    return parser


def _serialize_certificate(certificate: TLSCertificate) -> dict[str, object]:
    payload = asdict(certificate)
    payload["not_before"] = certificate.not_before.isoformat()
    payload["not_after"] = certificate.not_after.isoformat()
    return payload


def main() -> None:
    args = build_parser().parse_args()

    try:
        certificate = inspect_certificate(args.url, timeout=args.timeout)
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(f"error: {exc}") from exc

    if args.as_json:
        print(json.dumps(_serialize_certificate(certificate), indent=2))
        return

    print(f"hostname: {certificate.hostname}")
    print(f"subject: {certificate.subject}")
    print(f"issuer: {certificate.issuer}")
    print(f"serial number: {certificate.serial_number}")
    print(f"valid from: {certificate.not_before.isoformat()}")
    print(f"valid until: {certificate.not_after.isoformat()}")
    print(f"days remaining: {certificate.days_remaining}")


if __name__ == "__main__":
    main()
