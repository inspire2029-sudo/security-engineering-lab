from __future__ import annotations

import argparse

from .headers import inspect_headers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect common defensive HTTP security headers."
    )
    parser.add_argument("url", help="URL to inspect")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    for check in inspect_headers(args.url):
        status = "present" if check.present else "missing"
        print(f"{check.name}: {status}")

        if check.value:
            print(f"  value: {check.value}")


if __name__ == "__main__":
    main()
