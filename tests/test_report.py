import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from security_engineering_lab.headers import HeaderCheck
from security_engineering_lab.report import SiteSecurityReport, inspect_site
from security_engineering_lab.report_cli import main
from security_engineering_lab.tls import TLSCertificate


def make_certificate() -> TLSCertificate:
    return TLSCertificate(
        hostname="example.com",
        subject="commonName=example.com",
        issuer="commonName=Test CA",
        serial_number="ABC123",
        not_before=datetime(2030, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2031, 1, 1, tzinfo=timezone.utc),
        days_remaining=100,
    )


@patch("security_engineering_lab.report.inspect_certificate")
@patch("security_engineering_lab.report.inspect_headers")
def test_inspect_site_combines_http_and_tls_results(
    mock_headers, mock_certificate
):
    checks = [HeaderCheck("Content-Security-Policy", True, "default-src 'self'")]
    certificate = make_certificate()

    mock_headers.return_value = checks
    mock_certificate.return_value = certificate

    result = inspect_site("https://example.com", timeout=5)

    assert result == SiteSecurityReport(
        url="https://example.com",
        headers=checks,
        certificate=certificate,
    )
    mock_headers.assert_called_once_with("https://example.com", timeout=5)
    mock_certificate.assert_called_once_with("https://example.com", timeout=5)


@patch("security_engineering_lab.report.inspect_certificate")
@patch("security_engineering_lab.report.inspect_headers")
def test_inspect_site_skips_tls_for_http(mock_headers, mock_certificate):
    mock_headers.return_value = []

    result = inspect_site("http://example.com")

    assert result.url == "http://example.com"
    assert result.headers == []
    assert result.certificate is None
    mock_headers.assert_called_once_with("http://example.com", timeout=10.0)
    mock_certificate.assert_not_called()


def test_inspect_site_rejects_non_positive_timeout():
    with pytest.raises(ValueError, match="timeout must be greater than zero"):
        inspect_site("https://example.com", timeout=0)


@patch("security_engineering_lab.report_cli.inspect_site")
def test_report_cli_json_output(mock_inspect, monkeypatch, capsys):
    report = SiteSecurityReport(
        url="https://example.com",
        headers=[HeaderCheck("X-Content-Type-Options", True, "nosniff")],
        certificate=make_certificate(),
    )
    mock_inspect.return_value = report

    monkeypatch.setattr(
        "sys.argv",
        ["security-site-report", "https://example.com", "--json"],
    )

    main()

    payload = json.loads(capsys.readouterr().out)

    assert payload["url"] == "https://example.com"
    assert payload["headers"][0]["name"] == "X-Content-Type-Options"
    assert payload["certificate"]["not_before"] == "2030-01-01T00:00:00+00:00"


@patch("security_engineering_lab.report_cli.inspect_site")
def test_report_cli_passes_custom_timeout(mock_inspect, monkeypatch):
    mock_inspect.return_value = SiteSecurityReport(
        url="http://example.com",
        headers=[],
        certificate=None,
    )

    monkeypatch.setattr(
        "sys.argv",
        ["security-site-report", "http://example.com", "--timeout", "3.5"],
    )

    main()

    mock_inspect.assert_called_once_with("http://example.com", timeout=3.5)


@patch("security_engineering_lab.report_cli.inspect_site")
def test_report_cli_reports_errors_without_traceback(mock_inspect, monkeypatch, capsys):
    mock_inspect.side_effect = RuntimeError("HTTP request failed: timeout")

    monkeypatch.setattr(
        "sys.argv",
        ["security-site-report", "https://example.com"],
    )

    with pytest.raises(SystemExit, match="error: HTTP request failed: timeout"):
        main()

    assert capsys.readouterr().out == ""
