import json
from unittest.mock import Mock, patch

import pytest

from security_engineering_lab.cli import main
from security_engineering_lab.headers import (
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


@patch("security_engineering_lab.cli.inspect_headers")
def test_cli_json_output(mock_inspect, monkeypatch, capsys):
    mock_inspect.return_value = [
        Mock(name="Content-Security-Policy", present=True, value="default-src 'self'"),
        Mock(name="Strict-Transport-Security", present=False, value=None),
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
