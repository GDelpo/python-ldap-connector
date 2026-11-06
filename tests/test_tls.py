import logging
import ssl

import pytest
from ldap3 import AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND
from ldap3.core.exceptions import LDAPSSLConfigurationError

import main


@pytest.fixture
def ldap_env(monkeypatch):
    for name in ("LDAP_START_TLS", "LDAP_VERIFY_TLS", "LDAP_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LDAP_URL", "ldap://192.0.2.10")
    monkeypatch.setenv("LDAP_ADMIN_USERNAME", "svc-ldap@example.com")
    monkeypatch.setenv("LDAP_ADMIN_PASSWORD", "svc-pass")
    monkeypatch.setenv("LDAP_SEARCH_BASES", "OU=Users,DC=example,DC=com|OU=Staff,DC=example,DC=com")
    return monkeypatch


def test_verification_is_on_by_default():
    tls = main.build_tls()
    assert tls.validate == ssl.CERT_REQUIRED
    assert tls.ca_certs_file is None


def test_ca_bundle_is_used_and_keeps_verification_on(tmp_path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("fake CA, only the path is checked here\n")
    tls = main.build_tls(ca_bundle=str(bundle), verify=False)
    assert tls.validate == ssl.CERT_REQUIRED
    assert tls.ca_certs_file == str(bundle)


def test_missing_ca_bundle_fails_loudly(tmp_path):
    with pytest.raises(LDAPSSLConfigurationError):
        main.build_tls(ca_bundle=str(tmp_path / "missing.pem"))


def test_disabling_verification_is_explicit_and_logged(caplog):
    with caplog.at_level(logging.ERROR, logger="main"):
        tls = main.build_tls(verify=False)
    assert tls.validate == ssl.CERT_NONE
    assert "verification is disabled" in caplog.text


def test_env_defaults_to_start_tls_with_verification(ldap_env):
    settings = main.settings_from_env()
    assert settings["start_tls"] is True
    assert settings["tls"].validate == ssl.CERT_REQUIRED
    assert settings["ldap_search_bases"] == [
        "OU=Users,DC=example,DC=com",
        "OU=Staff,DC=example,DC=com",
    ]


def test_env_opt_outs(ldap_env):
    ldap_env.setenv("LDAP_START_TLS", "false")
    ldap_env.setenv("LDAP_VERIFY_TLS", "false")
    settings = main.settings_from_env()
    assert settings["start_tls"] is False
    assert settings["tls"].validate == ssl.CERT_NONE


def test_unclear_boolean_is_an_error(ldap_env):
    ldap_env.setenv("LDAP_VERIFY_TLS", "maybe")
    with pytest.raises(ValueError, match="LDAP_VERIFY_TLS"):
        main.settings_from_env()


def test_missing_url_is_an_error(ldap_env):
    ldap_env.delenv("LDAP_URL")
    with pytest.raises(ValueError, match="LDAP_URL"):
        main.settings_from_env()


def capture_auto_bind(monkeypatch):
    seen = []

    def fake_connection(server, **kwargs):
        seen.append((server, kwargs["auto_bind"]))
        raise main.LDAPSocketOpenError("no network in tests")

    monkeypatch.setattr(main, "Connection", fake_connection)
    return seen


def test_ldap_url_uses_start_tls_before_bind(monkeypatch):
    seen = capture_auto_bind(monkeypatch)
    service = main.UserLdapAuthorizationService("ldap://192.0.2.10", "svc@example.com", "pw")
    service.create_connection()
    server, auto_bind = seen[0]
    assert auto_bind == AUTO_BIND_TLS_BEFORE_BIND
    assert server.ssl is False
    assert server.tls.validate == ssl.CERT_REQUIRED


def test_ldaps_url_uses_tls_socket_without_start_tls(monkeypatch):
    seen = capture_auto_bind(monkeypatch)
    service = main.UserLdapAuthorizationService("ldaps://192.0.2.10", "svc@example.com", "pw")
    service.create_connection()
    server, auto_bind = seen[0]
    assert auto_bind == AUTO_BIND_NO_TLS
    assert server.ssl is True
    assert server.port == 636


def test_plain_ldap_only_when_explicit_and_logged(monkeypatch, caplog):
    seen = capture_auto_bind(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="main"):
        service = main.UserLdapAuthorizationService(
            "ldap://192.0.2.10", "svc@example.com", "pw", start_tls=False
        )
    service.create_connection()
    assert seen[0][1] == AUTO_BIND_NO_TLS
    assert "not encrypted" in caplog.text
