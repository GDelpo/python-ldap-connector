import logging

import pytest
from conftest import JDOE_DN, JDOE_PASSWORD, SVC_UPN, account_names


def spy_filters(monkeypatch, service):
    """Record the filter of every search the service sends."""
    service.create_connection()
    filters = []
    real_search = service.connection.search

    def search(*args, **kwargs):
        filters.append(kwargs["search_filter"])
        return real_search(*args, **kwargs)

    monkeypatch.setattr(service.connection, "search", search)
    return filters


# --- Filter escaping ---------------------------------------------------------------


def test_injection_payload_matches_nobody(monkeypatch, service):
    filters = spy_filters(monkeypatch, service)

    assert service.get_user_data(account_name="*)(objectClass=*") == {}
    assert r"(sAMAccountName=\2a\29\28objectClass=\2a)" in filters[0]
    assert r"\5c" not in filters[0]  # escaped once, not twice


def test_wildcard_in_account_name_is_literal(service):
    assert service.get_user_data(account_name="jdoe*") == {}


def test_parentheses_in_account_name_are_matched_literally(service):
    assert account_names(service.get_user_data(account_name="pat(ob)")) == {"pat(ob)"}


def test_injection_in_username_does_not_authenticate(service):
    assert service.authenticate_user("*", JDOE_PASSWORD) is False


# --- Service account as DN or UPN ---------------------------------------------------


def test_authenticate_with_dn_service_account(service):
    assert service.authenticate_user("jdoe", JDOE_PASSWORD) is True
    assert service.authenticate_user("jdoe", "wrong-pass") is False


def test_authenticate_with_upn_service_account(make_service):
    service = make_service(admin=SVC_UPN, admin_upn=True)
    assert service.authenticate_user("jdoe", JDOE_PASSWORD) is True
    assert service.authenticate_user("jdoe", "wrong-pass") is False


def test_authenticate_rejects_empty_password_and_unknown_user(service):
    assert service.authenticate_user("jdoe", "") is False
    assert service.authenticate_user("ghost", "whatever") is False


def test_bad_service_account_password_raises_instead_of_crashing(make_service):
    service = make_service(password="wrong")
    with pytest.raises(ConnectionError):
        service.get_user_data()


# --- Users without mail -------------------------------------------------------------


def test_users_without_mail_are_returned_by_default(service):
    users = service.get_user_data(attributes=["sAMAccountName", "mail"])
    assert "nomail" in account_names(users)
    no_mail = next(a for a in users.values() if a["sAMAccountName"] in ("nomail", ["nomail"]))
    assert not no_mail["mail"]


def test_require_mail_excludes_and_logs(service, caplog):
    with caplog.at_level(logging.INFO, logger="main"):
        users = service.get_user_data(attributes=["sAMAccountName", "mail"], require_mail=True)
    assert "nomail" not in account_names(users)
    assert "jdoe" in account_names(users)
    # nomail and the service account have no mail.
    assert "Users excluded for not having mail: 2" in caplog.text


# --- Paging and failed reads --------------------------------------------------------


def test_paging_collects_every_page(service):
    users = service.get_user_data(attributes=["sAMAccountName"], paged_size=1)
    # People only: the computer account is filtered out, the service account is a user.
    assert account_names(users) == {"svc-ldap", "jdoe", "jdoe2", "pat(ob)", "nomail", "sharedbox"}


def test_missing_paging_control_is_treated_as_last_page(monkeypatch, service, caplog):
    service.create_connection()
    connection = service.connection
    real_search = connection.search

    def search_without_control(*args, **kwargs):
        outcome = real_search(*args, **kwargs)
        connection.result.pop("controls", None)
        return outcome

    monkeypatch.setattr(connection, "search", search_without_control)
    with caplog.at_level(logging.WARNING, logger="main"):
        users = service.get_user_data(attributes=["sAMAccountName", "mail"])
    assert "jdoe" in account_names(users)
    assert "No paged results control" in caplog.text


def test_failed_search_raises_instead_of_returning_empty(make_service):
    import main

    service = make_service(bases=("OU=Missing,DC=example,DC=com",))
    with pytest.raises(main.DirectoryReadError, match="noSuchObject"):
        service.get_user_data()


def test_ou_to_avoid_skips_matching_users(service):
    users = service.get_user_data(ou_to_avoid=["OU=Shared Mailboxes"])
    assert "sharedbox" not in account_names(users)
    assert "jdoe" in account_names(users)


# --- DN helpers --------------------------------------------------------------------


def test_extract_cn_handles_escaped_comma_and_lowercase(service):
    assert service.extract_cn_from_dn(JDOE_DN) == r"Doe\, John"
    assert service.extract_cn_from_dn("cn=Ann Lee,ou=Users,dc=example,dc=com") == "Ann Lee"
    assert service.extract_cn_from_dn("OU=Users,DC=example,DC=com") is None


@pytest.mark.parametrize(("username", "password"), [("jdoe", ""), ("", "x"), ("jdoe", None)])
def test_empty_credentials_never_reach_the_directory(service, monkeypatch, username, password):
    """An empty password is refused before any lookup or bind (no unauthenticated bind)."""

    def must_not_run(*args, **kwargs):
        raise AssertionError("the directory was contacted with empty credentials")

    monkeypatch.setattr(service, "get_user_data", must_not_run)
    assert service.authenticate_user(username, password) is False
