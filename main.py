import logging
import os
import ssl
import sys
from functools import wraps
from pprint import pprint

from dotenv import load_dotenv
from ldap3 import (
    ALL,
    ALL_ATTRIBUTES,
    ALL_OPERATIONAL_ATTRIBUTES,
    AUTO_BIND_NO_TLS,
    AUTO_BIND_TLS_BEFORE_BIND,
    DEREF_ALWAYS,
    SIMPLE,
    SUBTREE,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPException,
    LDAPInvalidDnError,
    LDAPSocketOpenError,
)
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn

PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"

# Library logger: handlers are attached by configure_logging() when the script runs,
# so importing the class does not create files in the caller's folder.
log = logging.getLogger(__name__)


class DirectoryReadError(RuntimeError):
    """A directory search failed or returned an incomplete answer."""


def configure_logging():
    """Send this module's logs to ldap_service.log (used by the demo in __main__)."""
    # Set encoding to UTF-8 for stdout (console output) - Required for Windows OS
    sys.stdout.reconfigure(encoding="utf-8")

    log.setLevel(logging.DEBUG)  # level log

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    # File handler
    file_handler = logging.FileHandler("ldap_service.log")
    file_handler.setLevel(logging.DEBUG)

    # Log format
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    # console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # Add handlers
    # log.addHandler(console_handler)
    log.addHandler(file_handler)


def parse_bool(name: str, value: str | None, default: bool) -> bool:
    """Parse a true/false setting; anything that is not clearly one of them is an error."""
    if value is None or value.strip() == "":
        return default
    normalized = value.strip().lower()
    if normalized in ("true", "1", "yes"):
        return True
    if normalized in ("false", "0", "no"):
        return False
    raise ValueError(f"{name} must be true or false, got {value!r}.")


def build_tls(ca_bundle: str | None = None, verify: bool = True) -> Tls:
    """
    Build the TLS settings used for LDAPS and StartTLS.

    The server certificate is validated (chain and host name) against the system CAs, or
    against ca_bundle (a PEM file) when one is given. verify=False turns validation off,
    for lab servers only, and logs an error; a ca_bundle always keeps validation on.
    """
    if ca_bundle:
        # Tls() raises LDAPSSLConfigurationError when the file does not exist.
        return Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_bundle)
    if not verify:
        log.error("TLS certificate verification is disabled (LDAP_VERIFY_TLS=false).")
        return Tls(validate=ssl.CERT_NONE)
    # INTENTIONAL: ldap3's Tls defaults to validate=CERT_NONE, so the certificate would not
    # be checked at all unless CERT_REQUIRED is passed explicitly.
    return Tls(validate=ssl.CERT_REQUIRED)


def is_ldaps_url(ldap_url: str) -> bool:
    return ldap_url.strip().lower().startswith("ldaps://")


class UserLdapAuthorizationService:
    def __init__(
        self,
        ldap_url: str,
        ldap_admin_username: str,
        ldap_admin_password: str,
        ldap_search_bases: list[str] | None = None,
        start_tls: bool = True,
        tls: Tls | None = None,
    ):
        """
        Initialize the LDAP authorization service.

        Args:
            ldap_url (str): URL of the LDAP server (ldaps://host:636 or ldap://host:389).
            ldap_admin_username (str): Service account, as a UPN (svc@example.com) or a DN.
            ldap_admin_password (str): Password of the service account.
            ldap_search_bases (list, optional): List of search bases for LDAP queries.
            start_tls (bool): For ldap:// URLs, upgrade the connection with StartTLS before
                binding. False sends credentials in plain text and is logged as a warning.
                Ignored for ldaps:// URLs, which are TLS from the start.
            tls (Tls, optional): TLS settings; defaults to build_tls() (verification on).
        """
        self.ldap_url = ldap_url
        self.ldap_admin_username = ldap_admin_username
        self.ldap_admin_password = ldap_admin_password
        self.ldap_search_bases = ldap_search_bases if ldap_search_bases else []
        self.use_ssl = is_ldaps_url(ldap_url)
        self.start_tls = start_tls and not self.use_ssl
        self.tls = tls if tls is not None else build_tls()
        if not self.use_ssl and not self.start_tls:
            log.warning(
                "LDAP traffic is not encrypted: %s without StartTLS sends passwords in plain text.",
                ldap_url,
            )
        # ldap3 reads the ldaps:// scheme and opens the socket with TLS.
        self.server = Server(self.ldap_url, get_info=ALL, tls=self.tls)
        self.connection = None  # Initialize connection as None

    def test_connection(self):
        """
        Test the LDAP connection by attempting to bind with admin credentials.

        Raises:
            ConnectionError: If the connection could not be established.
        """
        self.create_connection()
        if not self.connection or not self.connection.bound:
            raise ConnectionError("Failed to establish LDAP connection.")

    def _open(self, user: str, password: str) -> Connection:
        """Open and bind a connection, with StartTLS first when it is configured."""
        return Connection(
            self.server,
            user=user,
            password=password,
            authentication=SIMPLE,
            auto_bind=AUTO_BIND_TLS_BEFORE_BIND if self.start_tls else AUTO_BIND_NO_TLS,
        )

    def create_connection(self):
        """
        Create a new connection to the LDAP server using admin credentials.
        """
        try:
            self.connection = self._open(self.ldap_admin_username, self.ldap_admin_password)
            log.info("Successfully connected to LDAP with admin credentials.")
        except LDAPBindError as e:
            log.error(f"LDAP authentication error: {str(e)}")
            self.connection = None
        except LDAPSocketOpenError as e:
            log.error(f"LDAP connection error: {str(e)}")
            self.connection = None
        except LDAPException as e:
            log.error(f"General LDAP error: {str(e)}")
            self.connection = None

    def close_connection(self):
        """
        Close the LDAP connection if it is open.
        """
        if self.connection:
            self.connection.unbind()
            log.info("LDAP connection closed.")

    def ensure_connection(func):
        """Decorator to ensure there is an active LDAP connection before executing a method."""

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if not self.connection or not self.connection.bound:
                self.create_connection()
            if not self.connection or not self.connection.bound:
                raise ConnectionError("Failed to establish LDAP connection.")
            return func(self, *args, **kwargs)

        return wrapper

    @ensure_connection
    def authenticate_user(self, username: str, password: str) -> bool:
        """
        Authenticate a specific user against the LDAP server.

        The user is looked up by sAMAccountName and the bind uses the DN the directory
        returns, so it works whether the service account is configured as a UPN or a DN.

        Args:
            username (str): The username to authenticate (e.g., 'jdoe').
            password (str): The user's password.

        Returns:
            bool: True if authentication is successful, False otherwise.
        """
        # INTENTIONAL: a simple bind with a DN and an empty password is an LDAP
        # "unauthenticated bind" that some servers accept; never send one.
        if not username or not password:
            log.warning("Authentication refused: empty username or password.")
            return False

        user_connection = None
        try:
            # Check if the user exists in LDAP before attempting authentication
            user_data = self.get_user_data(account_name=username, attributes=["sAMAccountName"])
            if not user_data:
                log.error(f"User {username} does not exist in LDAP.")
                return False
            if len(user_data) > 1:
                log.error(f"Authentication refused: {username} matches {len(user_data)} entries.")
                return False

            # Bind as the user's distinguished name (DN), as found by the search
            user_dn = next(iter(user_data))

            # Attempt to authenticate with the provided credentials
            user_connection = self._open(user_dn, password)
            log.info(f"Authentication successful for user {username}.")
            user_connection.unbind()  # Close the connection after successful authentication
            return True

        except LDAPBindError:
            log.error(f"Authentication failed: incorrect credentials for user {username}.")
        except LDAPSocketOpenError:
            log.error(f"Failed to establish a connection to the LDAP server for user {username}.")
        except LDAPException as e:
            log.error(f"Unexpected error during authentication of {username}: {str(e)}")
        except DirectoryReadError as e:
            log.error(f"Authentication of {username} aborted, user lookup failed: {e}")
        finally:
            if user_connection and user_connection.bound:
                user_connection.unbind()
                log.info("User connection closed after authentication attempt.")

        return False

    @ensure_connection
    def get_user_data(
        self,
        account_name=None,
        attributes=None,
        ou_to_avoid=None,
        paged_size=50,
        require_mail=False,
    ) -> dict:
        """
        Retrieve user data from the LDAP server.

        Args:
            account_name (str, optional): Specific account name to search for. Defaults to None.
            attributes (list, optional): List of attributes to retrieve for each user. Defaults to [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES].
            ou_to_avoid (list, optional): List of Organizational Units (OUs) to avoid. Defaults to an empty list.
            paged_size (int, optional): Number of entries to retrieve per page. Defaults to 50.
            require_mail (bool, optional): Only return users with a mail attribute. Defaults to
                False: users without mail are returned with an empty 'mail'. When True, each
                excluded user is logged and the total is logged at the end.

        Returns:
            dict: The retrieved users, keyed by Distinguished Name (DN); values are the user attributes.

        Raises:
            DirectoryReadError: If a search fails (bad base, size limit, server error).
            LDAPException: If the connection fails during the search.
        """
        if attributes is None:
            attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]

        if ou_to_avoid is None:
            ou_to_avoid = []

        users_data = {}
        excluded_without_mail = 0

        try:
            # Base filter for searching users
            search_filter = "(&(objectClass=user)(!(objectClass=computer)))"
            if account_name:
                # INTENTIONAL: escape_filter_chars, not a hand-written replace loop; a loop
                # that escapes "*" first and "\" later turns "\2a" into "\5c2a".
                search_filter = (
                    f"(&{search_filter}(sAMAccountName={escape_filter_chars(account_name)}))"
                )

            for search_base in self.ldap_search_bases:
                log.info(f"Searching users in base: {search_base}")
                cookie = None

                while True:
                    self.connection.search(
                        search_base=search_base,
                        search_filter=search_filter,
                        search_scope=SUBTREE,
                        dereference_aliases=DEREF_ALWAYS,
                        attributes=attributes,
                        paged_size=paged_size,
                        paged_cookie=cookie,
                    )
                    result = self.connection.result
                    # search() returns False both on errors and on "no entries", so the
                    # result code is what tells them apart.
                    if result.get("result") != 0:
                        raise DirectoryReadError(
                            f"Search in {search_base} failed: {result.get('description')} "
                            f"({result.get('message')})"
                        )

                    for entry in self.connection.response:
                        if "dn" in entry:
                            dn = entry["dn"]
                            if any(ou in dn for ou in ou_to_avoid):
                                log.info(f"Skipping user in {dn} due to match with OU to avoid.")
                                continue

                            if require_mail and not entry["attributes"].get("mail"):
                                excluded_without_mail += 1
                                log.info(f"User {dn} excluded: no mail and require_mail=True.")
                                continue

                            users_data[dn] = entry["attributes"]
                            log.debug(f"User found: {self.extract_cn_from_dn(dn)} ({dn})")
                        else:
                            log.warning(f"Entry without 'dn' found: {entry}")

                    # Retrieve cookie for paged search
                    control = (result.get("controls") or {}).get(PAGED_RESULTS_OID)
                    if control is None:
                        # The server answered with success but without the paging control
                        # (it ignored the non-critical control): the answer is complete.
                        log.warning(
                            f"No paged results control in the answer for {search_base}; "
                            "treating it as the last page."
                        )
                        break
                    cookie = control["value"]["cookie"]
                    if not cookie:
                        break

            log.info(f"Total users retrieved: {len(users_data)}")
            if excluded_without_mail:
                log.info(f"Users excluded for not having mail: {excluded_without_mail}")
            return users_data
        except LDAPException as e:
            log.error(f"Error retrieving users: {str(e)}")
            raise

    def extract_cn_from_dn(self, dn: str) -> str | None:
        """
        Extract the Common Name (CN) from a Distinguished Name (DN).

        Args:
            dn (str): The full Distinguished Name.

        Returns:
            str: The value of the CN, or None if not found.
        """
        try:
            components = parse_dn(dn, escape=False, strip=True)
        except LDAPInvalidDnError:
            return None
        for attribute_type, value, _separator in components:
            if attribute_type.upper() == "CN":
                # The value keeps its RFC 4514 escapes, e.g. "Doe\, John".
                return value
        return None


def settings_from_env() -> dict:
    """Read the connection settings from environment variables."""
    ldap_url = os.getenv("LDAP_URL")  # LDAP server URL
    if not ldap_url:
        raise ValueError("LDAP_URL is not set.")
    return {
        "ldap_url": ldap_url,
        # Administrative user for initial connection (UPN or DN)
        "ldap_admin_username": os.getenv("LDAP_ADMIN_USERNAME"),
        # Password for the administrative user
        "ldap_admin_password": os.getenv("LDAP_ADMIN_PASSWORD"),
        # Initial search bases
        "ldap_search_bases": (lambda x: x.split("|") if x else [])(os.getenv("LDAP_SEARCH_BASES")),
        "start_tls": parse_bool("LDAP_START_TLS", os.getenv("LDAP_START_TLS"), default=True),
        "tls": build_tls(
            ca_bundle=os.getenv("LDAP_CA_BUNDLE") or None,
            verify=parse_bool("LDAP_VERIFY_TLS", os.getenv("LDAP_VERIFY_TLS"), default=True),
        ),
    }


if __name__ == "__main__":
    configure_logging()

    # Load environment variables from the .env file
    load_dotenv()

    # List of OUs to avoid
    ou_to_avoid = ["OU=Shared Mailboxes"]
    attributes_to_get = [
        "sAMAccountName",
        "mail",
        "whenCreated",
        "whenChanged",
    ]  # Attributes to retrieve

    ldap_service = UserLdapAuthorizationService(**settings_from_env())

    try:
        ldap_service.test_connection()
        # Test authentication with a valid user
        print(ldap_service.authenticate_user("username without dn", "password"))
        # Test authentication with an invalid user
        print(ldap_service.authenticate_user("invalid_user", "invalid_password"))
        # Retrieve user data for a specific user
        user_data = ldap_service.get_user_data(
            attributes=attributes_to_get, ou_to_avoid=ou_to_avoid, account_name="jdoe"
        )
        pprint(user_data)
    except ConnectionError as e:
        log.error(f"Connection error: {str(e)}")
    finally:
        ldap_service.close_connection()
