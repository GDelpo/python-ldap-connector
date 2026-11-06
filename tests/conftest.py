import os
import sys
import tempfile
from pathlib import Path

import ldap3
import pytest
from ldap3 import MOCK_SYNC
from ldap3.core.exceptions import LDAPBindError

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Fake directory: example.com names and an RFC 5737 address; nothing reaches a real server.
LDAP_URL = "ldaps://192.0.2.10"
BASE = "DC=example,DC=com"
SVC_DN = "CN=svc-ldap,OU=Service Accounts,DC=example,DC=com"
SVC_UPN = "svc-ldap@example.com"
SVC_PASSWORD = "svc-pass"
JDOE_DN = r"CN=Doe\, John,OU=Users,DC=example,DC=com"
JDOE_PASSWORD = "jdoe-pass"

USERS = {
    JDOE_DN: {
        "sAMAccountName": "jdoe",
        "mail": "jdoe@example.com",
        "userPrincipalName": "jdoe@example.com",
        "userPassword": JDOE_PASSWORD,
    },
    "CN=Jane Doe,OU=Users,DC=example,DC=com": {
        "sAMAccountName": "jdoe2",
        "mail": "jane.doe@example.com",
        "userPassword": "jdoe2-pass",
    },
    "CN=Pat O'Brien,OU=Users,DC=example,DC=com": {
        "sAMAccountName": "pat(ob)",
        "mail": "pat@example.com",
    },
    "CN=No Mail,OU=Users,DC=example,DC=com": {"sAMAccountName": "nomail"},
    "CN=Shared Box,OU=Shared Mailboxes,DC=example,DC=com": {
        "sAMAccountName": "sharedbox",
        "mail": "shared@example.com",
    },
}


def pytest_sessionstart(session):
    # INTENTIONAL: run from a temp dir so nothing the module writes (ldap_service.log)
    # lands in the repo.
    os.chdir(tempfile.mkdtemp(prefix="ldap-tests-"))


def account_names(users: dict) -> set[str]:
    """sAMAccountName of every returned user (the mock returns it as a list)."""
    names = set()
    for attributes in users.values():
        value = attributes["sAMAccountName"]
        names.update(value if isinstance(value, list) else [value])
    return names


def build_server(admin_upn: bool = False) -> ldap3.Server:
    """An in-memory server (ldap3 MOCK_SYNC) loaded with fake AD entries."""
    server = ldap3.Server(LDAP_URL)
    seed = ldap3.Connection(server, client_strategy=MOCK_SYNC)
    seed.strategy.add_entry(
        SVC_DN,
        {
            "objectClass": ["top", "person", "user"],
            "sAMAccountName": "svc-ldap",
            "userPassword": SVC_PASSWORD,
        },
    )
    for dn, attributes in USERS.items():
        seed.strategy.add_entry(
            dn, {"objectClass": ["top", "person", "organizationalPerson", "user"], **attributes}
        )
    seed.strategy.add_entry(
        "CN=WS01,OU=Computers,DC=example,DC=com",
        {"objectClass": ["top", "user", "computer"], "sAMAccountName": "WS01$"},
    )
    if admin_upn:
        # INTENTIONAL: the mock only binds by DN. AD also accepts a UPN, so register the
        # UPNs as extra bind identities (not entries: they are not valid DNs).
        server.dit[SVC_UPN] = {"userPassword": [SVC_PASSWORD.encode()]}
        server.dit["jdoe@example.com"] = {"userPassword": [JDOE_PASSWORD.encode()]}
    return server


@pytest.fixture
def make_service(monkeypatch):
    """Build a UserLdapAuthorizationService wired to the fake directory."""
    import main

    def factory(admin=SVC_DN, password=SVC_PASSWORD, bases=(BASE,), admin_upn=False):
        server = build_server(admin_upn=admin_upn)
        real_connection = ldap3.Connection

        def fake_server(*args, **kwargs):
            return server

        def fake_connection(*args, **kwargs):
            kwargs["client_strategy"] = MOCK_SYNC
            auto_bind = kwargs.pop("auto_bind", False)
            connection = real_connection(*args, **kwargs)
            # INTENTIONAL: MOCK_SYNC ignores auto_bind, so bind here and fail the way a
            # real auto_bind does. StartTLS is not emulated (the fake URL is ldaps://).
            if auto_bind and not connection.bind():
                raise LDAPBindError(f"automatic bind not successful - {connection.last_error}")
            return connection

        monkeypatch.setattr(main, "Server", fake_server)
        monkeypatch.setattr(main, "Connection", fake_connection)
        return main.UserLdapAuthorizationService(
            ldap_url=LDAP_URL,
            ldap_admin_username=admin,
            ldap_admin_password=password,
            ldap_search_bases=list(bases),
        )

    return factory


@pytest.fixture
def service(make_service):
    return make_service()
