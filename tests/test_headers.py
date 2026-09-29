import json
from unittest.mock import Mock, patch

import pytest
import requests

from security_engineering_lab.cli import main
from security_engineering_lab.headers import (
    HeaderCheck,
    RECOMMENDED_HEADERS,
    inspect_headers,
    validate_url,
)


def test_validate_url_accepts_http_and_https():
    assert validate_url("http://example.com") == "http://example.com"
    assert validate_url("https://example.com") == "https://example.com"


@pytest.mark.parametrize(
    "url",
    [
        "example.com",
        "ftp://example.com",
        "https://",
    ],
)
def test_validate_url_rejects_invalid_urls(url):
    with pytest.raises(ValueError):
        validate_url(url)


def test_inspect_headers_rejects_non_positive_timeout():
    with pytest.raises(ValueError, match="timeout must be greater than zero"):
        inspect_headers("https://example.com", timeout=0)


@pytest.mark.parametrize(
    "headers, expected_present",
    [
        (
            {
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=()",
            },
            True,
        ),
        ({}, False),
    ],
)
@patch("security_engineering_lab.headers.requests.get")
def test_inspect_headers_handles_complete_and_empty_results(
    mock_get, headers, expected_present
):
    response = Mock()
    response.headers = headers
    response.raise_for_status.return_value = None
    mock_get.return_value = response

    checks = inspect_headers("https://example.com")

    assert len(checks) == len(RECOMMENDED_HEADERS)
    assert all(check.present is expected_present for check in checks)


@patch("security_engineering_lab.headers.requests.get")
def test_inspect_headers_reports_presence(mock_get):
    response = Mock()
    response.headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
    }
    response.raise_for_status.return_value = None
    mock_get.return_value = response

    checks = inspect_headers("https://example.com")

    assert len(checks) == len(RECOMMENDED_HEADERS)

    by_name = {check.name: check for check in checks}

    assert by_name["Content-Security-Policy"].present is True
    assert by_name["Content-Security-Policy"].value == "default-src 'self'"
    assert by_name["X-Content-Type-Options"].present is True
    assert by_name["Strict-Transport-Security"].present is False


@patch("security_engineering_lab.headers.requests.get")
def test_inspect_headers_uses_timeout_and_follows_redirects(mock_get):
    response = Mock()
    response.headers = {}
    response.raise_for_status.return_value = None
    mock_get.return_value = response

    inspect_headers("https://example.com", timeout=5)

    mock_get.assert_called_once_with(
        "https://example.com",
        timeout=5,
        allow_redirects=True,
    )


@patch("security_engineering_lab.headers.requests.get")
def test_inspect_headers_wraps_request_errors(mock_get):
    mock_get.side_effect = requests.Timeout("connection timed out")

    with pytest.raises(RuntimeError, match="HTTP request failed"):
        inspect_headers("https://example.com")


@patch("security_engineering_lab.headers.requests.get")
def test_inspect_headers_wraps_http_errors(mock_get):
    response = Mock()
    response.headers = {}
    response.raise_for_status.side_effect = requests.HTTPError("404")
    mock_get.return_value = response

    with pytest.raises(RuntimeError, match="HTTP request failed"):
        inspect_headers("https://example.com")


@patch("security_engineering_lab.cli.inspect_headers")
def test_cli_json_output(mock_inspect, monkeypatch, capsys):
    mock_inspect.return_value = [
        HeaderCheck(
            name="Content-Security-Policy",
            present=True,
            value="default-src 'self'",
        ),
        HeaderCheck(
            name="Strict-Transport-Security",
            present=False,
            value=None,
        ),
    ]

    monkeypatch.setattr(
        "sys.argv",
        ["security-header-inspector", "https://example.com", "--json"],
    )

    main()

    payload = json.loads(capsys.readouterr().out)

    assert payload == [
        {
            "name": "Content-Security-Policy",
            "present": True,
            "value": "default-src 'self'",
        },
        {
            "name": "Strict-Transport-Security",
            "present": False,
            "value": None,
        },
    ]


@patch("security_engineering_lab.cli.inspect_headers")
def test_cli_passes_custom_timeout(mock_inspect, monkeypatch):
    mock_inspect.return_value = []

    monkeypatch.setattr(
        "sys.argv",
        ["security-header-inspector", "https://example.com", "--timeout", "3.5"],
    )

    main()

    mock_inspect.assert_called_once_with("https://example.com", timeout=3.5)


@patch("security_engineering_lab.cli.inspect_headers")
def test_cli_reports_errors_without_traceback(mock_inspect, monkeypatch, capsys):
    mock_inspect.side_effect = RuntimeError("HTTP request failed: timeout")

    monkeypatch.setattr(
        "sys.argv",
        ["security-header-inspector", "https://example.com"],
    )

    with pytest.raises(SystemExit, match="error: HTTP request failed: timeout"):
        main()

    assert capsys.readouterr().out == ""
