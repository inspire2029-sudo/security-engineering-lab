from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .report import SiteSecurityReport, inspect_site


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run passive HTTP header and TLS certificate inspections."
    )
    parser.add_argument("url", help="HTTP or HTTPS URL to inspect")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Network timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Print the complete report as JSON.",
    )
    return parser


def _serialize_report(report: SiteSecurityReport) -> dict[str, object]:
    payload = asdict(report)

    if report.certificate is not None:
        payload["certificate"]["not_before"] = report.certificate.not_before.isoformat()
        payload["certificate"]["not_after"] = report.certificate.not_after.isoformat()

    return payload


def main() -> None:
    args = build_parser().parse_args()

    try:
        report = inspect_site(args.url, timeout=args.timeout)
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(f"error: {exc}") from exc

    if args.as_json:
        print(json.dumps(_serialize_report(report), indent=2))
        return

    print(f"url: {report.url}")
    print("HTTP security headers:")

    for check in report.headers:
        status = "present" if check.present else "missing"
        print(f"  {check.name}: {status}")
        if check.value:
            print(f"    value: {check.value}")

    if report.certificate is not None:
        print("TLS certificate:")
        print(f"  subject: {report.certificate.subject}")
        print(f"  issuer: {report.certificate.issuer}")
        print(f"  valid until: {report.certificate.not_after.isoformat()}")
        print(f"  days remaining: {report.certificate.days_remaining}")
    else:
        print("TLS certificate: not applicable for HTTP")


if __name__ == "__main__":
    main()
