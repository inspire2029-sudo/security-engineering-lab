from __future__ import annotations

import argparse
import json

from .headers import HeaderCheck, inspect_headers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect common defensive HTTP security headers."
    )
    parser.add_argument("url", help="URL to inspect")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Print the inspection result as JSON.",
    )
    return parser


def _serialize_checks(checks: list[HeaderCheck]) -> list[dict[str, object]]:
    return [
        {
            "name": check.name,
            "present": check.present,
            "value": check.value,
        }
        for check in checks
    ]


def main() -> None:
    args = build_parser().parse_args()
    checks = inspect_headers(args.url)

    if args.as_json:
        print(json.dumps(_serialize_checks(checks), indent=2))
        return

    for check in checks:
        status = "present" if check.present else "missing"
        print(f"{check.name}: {status}")

        if check.value:
            print(f"  value: {check.value}")


if __name__ == "__main__":
    main()
