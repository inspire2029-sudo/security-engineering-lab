from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import ssl

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


@patch("security_engineering_lab.tls.socket.create_connection")
@patch("security_engineering_lab.tls.ssl.create_default_context")
def test_inspect_certificate_parses_certificate(
    mock_context_factory, mock_create_connection
):
    certificate = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("commonName", "Test CA"),),),
        "serialNumber": "ABC123",
        "notBefore": "Jan 01 00:00:00 2030 GMT",
        "notAfter": "Jan 01 00:00:00 2031 GMT",
    }

    raw_socket = MagicMock()
    tls_socket = MagicMock()
    tls_socket.getpeercert.return_value = certificate

    mock_create_connection.return_value.__enter__.return_value = raw_socket
    mock_context_factory.return_value.wrap_socket.return_value.__enter__.return_value = (
        tls_socket
    )

    result = inspect_certificate("https://example.com", timeout=5)

    assert result.hostname == "example.com"
    assert result.subject == "commonName=example.com"
    assert result.issuer == "commonName=Test CA"
    assert result.serial_number == "ABC123"
    assert result.not_before == datetime(2030, 1, 1, tzinfo=timezone.utc)
    assert result.not_after == datetime(2031, 1, 1, tzinfo=timezone.utc)


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
