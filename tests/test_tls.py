from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import ssl

import pytest

from security_engineering_lab.tls import (
    inspect_certificate,
    validate_https_url,
)


def test_validate_https_url_accepts_https():
    assert validate_https_url("https://example.com") == ("example.com", 443)
    assert validate_https_url("https://example.com:8443") == ("example.com", 8443)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "example.com",
        "ftp://example.com",
        "https://",
    ],
)
def test_validate_https_url_rejects_non_https(url):
    with pytest.raises(ValueError):
        validate_https_url(url)


def test_inspect_certificate_rejects_non_positive_timeout():
    with pytest.raises(ValueError, match="timeout must be greater than zero"):
        inspect_certificate("https://example.com", timeout=0)


@patch("security_engineering_lab.tls.datetime")
@patch("security_engineering_lab.tls.socket.create_connection")
@patch("security_engineering_lab.tls.ssl.create_default_context")
def test_inspect_certificate_parses_certificate_and_calculates_remaining_days(
    mock_context_factory, mock_create_connection, mock_datetime
):
    certificate = {
        "subject": ((( "commonName", "example.com"),),),
        "issuer": ((( "commonName", "Test CA"),),),
        "serialNumber": "ABC123",
        "notBefore": "Jan 01 00:00:00 2030 GMT",
        "notAfter": "Jan 11 00:00:00 2030 GMT",
    }

    raw_socket = MagicMock()
    tls_socket = MagicMock()
    tls_socket.getpeercert.return_value = certificate

    mock_create_connection.return_value.__enter__.return_value = raw_socket
    mock_context_factory.return_value.wrap_socket.return_value.__enter__.return_value = (
        tls_socket
    )

    current_time = datetime(2030, 1, 1, tzinfo=timezone.utc)
    mock_datetime.now.return_value = current_time
    mock_datetime.strptime.side_effect = datetime.strptime

    result = inspect_certificate("https://example.com", timeout=5)

    assert result.hostname == "example.com"
    assert result.subject == "commonName=example.com"
    assert result.issuer == "commonName=Test CA"
    assert result.serial_number == "ABC123"
    assert result.not_before == datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert result.not_after == datetime(2030, 1, 11, tzinfo=timezone.utc)
    assert result.days_remaining == 10


@patch("security_engineering_lab.tls.socket.create_connection")
@patch("security_engineering_lab.tls.ssl.create_default_context")
def test_inspect_certificate_uses_hostname_for_tls_sni(
    mock_context_factory, mock_create_connection
):
    certificate = {
        "subject": (),
        "issuer": (),
        "serialNumber": "ABC123",
        "notBefore": "Jan 01 00:00:00 2030 GMT",
        "notAfter": "Jan 11 00:00:00 2030 GMT",
    }

    raw_socket = MagicMock()
    tls_socket = MagicMock()
    tls_socket.getpeercert.return_value = certificate

    mock_create_connection.return_value.__enter__.return_value = raw_socket
    mock_context_factory.return_value.wrap_socket.return_value.__enter__.return_value = (
        tls_socket
    )

    result = inspect_certificate("https://example.com:8443", timeout=5)

    assert result.hostname == "example.com"
    mock_create_connection.assert_called_once_with("example.com", 8443, timeout=5)
    mock_context_factory.return_value.wrap_socket.assert_called_once_with(
        raw_socket,
        server_hostname="example.com",
    )


@patch("security_engineering_lab.tls.socket.create_connection")
def test_inspect_certificate_wraps_connection_errors(mock_create_connection):
    mock_create_connection.side_effect = TimeoutError("timed out")

    with pytest.raises(RuntimeError, match="TLS connection failed"):
        inspect_certificate("https://example.com")


@patch("security_engineering_lab.tls.socket.create_connection")
def test_inspect_certificate_wraps_tls_errors(mock_create_connection):
    mock_create_connection.side_effect = ssl.SSLError("certificate failure")

    with pytest.raises(RuntimeError, match="TLS connection failed"):
        inspect_certificate("https://example.com")


@patch("security_engineering_lab.tls.socket.create_connection")
@patch("security_engineering_lab.tls.ssl.create_default_context")
def test_inspect_certificate_rejects_malformed_validity(
    mock_context_factory, mock_create_connection
):
    certificate = {
        "subject": (),
        "issuer": (),
        "serialNumber": "ABC123",
        "notBefore": "not-a-date",
        "notAfter": "also-not-a-date",
    }

    tls_socket = MagicMock()
    tls_socket.getpeercert.return_value = certificate

    mock_create_connection.return_value.__enter__.return_value = MagicMock()
    mock_context_factory.return_value.wrap_socket.return_value.__enter__.return_value = (
        tls_socket
    )

    with pytest.raises(
        RuntimeError, match="TLS certificate has an invalid validity period"
    ):
        inspect_certificate("https://example.com")


@patch("security_engineering_lab.tls.socket.create_connection")
@patch("security_engineering_lab.tls.ssl.create_default_context")
def test_inspect_certificate_rejects_missing_validity(
    mock_context_factory, mock_create_connection
):
    certificate = {
        "subject": (),
        "issuer": (),
        "serialNumber": "ABC123",
    }

    tls_socket = MagicMock()
    tls_socket.getpeercert.return_value = certificate

    mock_create_connection.return_value.__enter__.return_value = MagicMock()
    mock_context_factory.return_value.wrap_socket.return_value.__enter__.return_value = (
        tls_socket
    )

    with pytest.raises(
        RuntimeError, match="TLS certificate has an invalid validity period"
    ):
        inspect_certificate("https://example.com")


@patch("security_engineering_lab.tls_cli.inspect_certificate")
def test_tls_cli_json_output(mock_inspect, monkeypatch, capsys):
    certificate = SimpleNamespace(
        hostname="example.com",
        subject="commonName=example.com",
        issuer="commonName=Test CA",
        serial_number="ABC123",
        not_before=datetime(2030, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2031, 1, 1, tzinfo=timezone.utc),
        days_remaining=100,
    )
    mock_inspect.return_value = certificate

    monkeypatch.setattr(
        "sys.argv",
        ["tls-certificate-inspector", "https://example.com", "--json"],
    )

    from security_engineering_lab.tls_cli import main

    main()

    payload = __import__("json").loads(capsys.readouterr().out)

    assert payload["hostname"] == "example.com"
    assert payload["serial_number"] == "ABC123"
    assert payload["not_before"] == "2030-01-01T00:00:00+00:00"
    assert payload["not_after"] == "2031-01-01T00:00:00+00:00"
    assert payload["days_remaining"] == 100


@patch("security_engineering_lab.tls_cli.inspect_certificate")
def test_tls_cli_passes_custom_timeout(mock_inspect, monkeypatch):
    mock_inspect.return_value = SimpleNamespace(
        hostname="example.com",
        subject="",
        issuer="",
        serial_number="",
        not_before=datetime(2030, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2031, 1, 1, tzinfo=timezone.utc),
        days_remaining=100,
    )

    monkeypatch.setattr(
        "sys.argv",
        ["tls-certificate-inspector", "https://example.com", "--timeout", "3.5"],
    )

    from security_engineering_lab.tls_cli import main

    main()

    mock_inspect.assert_called_once_with("https://example.com", timeout=3.5)


@patch("security_engineering_lab.tls_cli.inspect_certificate")
def test_tls_cli_reports_errors_without_traceback(mock_inspect, monkeypatch, capsys):
    mock_inspect.side_effect = RuntimeError("TLS connection failed: timeout")

    monkeypatch.setattr(
        "sys.argv",
        ["tls-certificate-inspector", "https://example.com"],
    )

    from security_engineering_lab.tls_cli import main

    with pytest.raises(SystemExit, match="error: TLS connection failed: timeout"):
        main()

    assert capsys.readouterr().out == ""
