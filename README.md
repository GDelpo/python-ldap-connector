# python-ldap-connector

<p>
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
</p>

> A small Python class that authenticates users against Active Directory over LDAP and reads their attributes, with paged searches, OU exclusion and TLS on by default.

## Features

- Binds with a service account, given as a UPN (`svc-ldap@example.com`) or a DN (`CN=svc-ldap,OU=Service Accounts,DC=example,DC=com`).
- `authenticate_user()` looks the user up by `sAMAccountName` and binds as the DN the directory returns. Unknown users, wrong or empty passwords, and names that match more than one entry return `False`.
- `get_user_data()` runs a paged search over one or more bases and returns the users keyed by DN. It skips computer accounts and any DN that contains one of the `ou_to_avoid` strings.
- The account name is escaped with `ldap3.utils.conv.escape_filter_chars`, so `*`, `(`, `)` and `\` in a name are matched literally instead of changing the filter.
- Users without a `mail` attribute are returned with an empty `mail`. Pass `require_mail=True` to leave them out; each exclusion and the total are logged.
- A search that fails (bad base, size limit, server error) raises `DirectoryReadError` instead of returning an empty result. An answer without the paged-results control is treated as the last page and logged as a warning.
- TLS: `ldaps://` URLs use TLS from the start and `ldap://` URLs upgrade with StartTLS before the bind. The server certificate is checked against the system CAs or a CA bundle you provide.

## Requirements

- Python 3.10+ (`python-dotenv` 1.2 needs 3.10, and the code uses `X | None` annotations).
- **Active Directory only.** The filters use `objectClass=user`, `objectClass=computer` and `sAMAccountName`, which OpenLDAP and other directories do not have by default.
- A service account that can read the users under the search bases.

## Quickstart

### Install

```bash
git clone https://github.com/GDelpo/python-ldap-connector.git
cd python-ldap-connector
python -m venv env
source env/bin/activate          # Windows: .\env\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env             # then fill in the values for your directory
```

### Run

```bash
python main.py
```

`main.py` runs a demo: `test_connection()`, two `authenticate_user()` calls and a `get_user_data()` lookup for `jdoe`. Logs go to `ldap_service.log` in the current folder.

## Configuration

`settings_from_env()` reads these variables; `main.py` loads them from `.env`.

| Variable | Description |
|----------|-------------|
| `LDAP_URL` | Server URL: `ldaps://dc01.example.com:636` (TLS) or `ldap://dc01.example.com:389` (StartTLS). Required. |
| `LDAP_ADMIN_USERNAME` | Service account, as a UPN or a DN. |
| `LDAP_ADMIN_PASSWORD` | Password for the service account. |
| `LDAP_SEARCH_BASES` | Search base DNs, separated by `\|`. |
| `LDAP_START_TLS` | Optional, default `true`. Only for `ldap://` URLs. `false` sends credentials in plain text and logs a warning. |
| `LDAP_VERIFY_TLS` | Optional, default `true`. `false` turns certificate verification off, for lab servers only, and logs an error. |
| `LDAP_CA_BUNDLE` | Optional. Path to a PEM file with the CA that signs the server certificate. When it is set, verification stays on. |

Boolean values accept `true`/`false`, `1`/`0` and `yes`/`no`; anything else is an error.

## Usage

```python
from main import UserLdapAuthorizationService, build_tls

ldap = UserLdapAuthorizationService(
    ldap_url="ldaps://dc01.example.com:636",
    ldap_admin_username="svc-ldap@example.com",
    ldap_admin_password="...",
    ldap_search_bases=["OU=Users,DC=example,DC=com"],
    tls=build_tls(ca_bundle="/etc/ssl/certs/example-ca.pem"),
)

ldap.test_connection()
ldap.authenticate_user("jdoe", "password")  # True / False
users = ldap.get_user_data(
    account_name="jdoe",
    attributes=["sAMAccountName", "mail", "whenCreated"],
    ou_to_avoid=["OU=Shared Mailboxes"],
)
# {"CN=Doe\\, John,OU=Users,DC=example,DC=com": {"sAMAccountName": "jdoe", "mail": "jdoe@example.com", ...}}
```

Without `attributes`, every user and operational attribute is returned. `example_persona_all_attrs.txt` shows what that looks like for an AD user (made-up data).

`ou_to_avoid` is a plain, case-sensitive substring match on the DN.

## Tests

```bash
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
pytest
```

The tests run against an in-memory directory (ldap3's `MOCK_SYNC` strategy) loaded with fake AD entries under `example.com`, so they need no server. They cover filter escaping (an injected `*)(objectClass=*`, literal `*` and parentheses), authentication with the service account as a DN or a UPN, wrong and empty passwords, users without mail with and without `require_mail`, paging across pages, an answer without the paging control, a failed search, `ou_to_avoid`, CN extraction from escaped DNs, and the TLS settings (verification default, CA bundle, explicit opt-out, StartTLS versus LDAPS, plain `ldap://`). StartTLS and certificate checks against a real server are not covered. CI runs them on Python 3.10 and 3.14.

## Architecture

```
python-ldap-connector/
├── main.py                          # UserLdapAuthorizationService, TLS helpers + demo
├── example_persona_all_attrs.txt    # sample AD attributes (made-up data)
├── tests/                           # pytest suite with a MOCK_SYNC directory
├── requirements.txt                 # runtime pins
├── requirements-dev.txt             # pytest + ruff
├── .env.example
└── LICENSE
```

Built on [`ldap3`](https://ldap3.readthedocs.io/).

## License

[MIT](LICENSE) © 2026 Guido Delponte
