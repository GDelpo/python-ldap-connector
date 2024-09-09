import sys
from typing import List
from ldap3 import Server, Connection, SIMPLE, SUBTREE, ALL, DEREF_ALWAYS, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError
import logging
from pprint import pprint
from dotenv import load_dotenv
import os

# Set encoding to UTF-8 for stdout (console output) - Required for Windows OS    
sys.stdout.reconfigure(encoding='utf-8')

# Config log
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)  # level log

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# File handler
file_handler = logging.FileHandler('ldap_service.log')
file_handler.setLevel(logging.DEBUG)

# Log format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

# Add handlers
#log.addHandler(console_handler)
log.addHandler(file_handler)

class UserLdapAuthorizationService:
    def __init__(self, ldap_url: str, ldap_admin_username: str, ldap_admin_password: str, ldap_search_bases:List[str]|None=None):
        """
        Initialize the LDAP authorization service.
        
        Args:
            ldap_url (str): URL of the LDAP server.
            ldap_admin_username (str): Username of the LDAP admin.
            ldap_admin_password (str): Password of the LDAP admin.
            ldap_search_bases (list, optional): List of search bases for LDAP queries.
        """
        self.ldap_url = ldap_url
        self.ldap_admin_username = ldap_admin_username
        self.ldap_admin_password = ldap_admin_password
        self.ldap_search_bases = ldap_search_bases if ldap_search_bases else []
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

    def create_connection(self):
        """
        Create a new connection to the LDAP server using admin credentials.
        """
        try:
            server = Server(self.ldap_url, get_info=ALL)
            self.connection = Connection(
                server,
                user=self.ldap_admin_username,
                password=self.ldap_admin_password,
                authentication=SIMPLE,
                auto_bind=True
            )
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
        def wrapper(self, *args, **kwargs):
            if not self.connection or not self.connection.bound:
                self.create_connection()
            return func(self, *args, **kwargs)
        return wrapper

    @ensure_connection
    def authenticate_user(self, username: str, password: str) -> bool:
        """
        Authenticate a specific user against the LDAP server.
        
        Args:
            username (str): The username to authenticate (e.g., 'jdoe').
            password (str): The user's password.
        
        Returns:
            bool: True if authentication is successful, False otherwise.            
        """
        user_connection = None
        try:
            # Check if the user exists in LDAP before attempting authentication
            user_data = self.get_user_data(account_name=username)
            if not user_data:
                log.error(f"User {username} does not exist in LDAP.")
                return False

            # Construct the user's distinguished name (DN)
            user_dn = f"{username}@{self.ldap_admin_username.split('@')[1]}"

            # Attempt to authenticate with the provided credentials
            user_connection = Connection(
                self.connection.server,
                user=user_dn,
                password=password,
                authentication=SIMPLE,
                auto_bind=True
            )
            log.info(f"Authentication successful for user {username}.")
            user_connection.unbind()  # Close the connection after successful authentication
            return True

        except LDAPBindError:
            log.error(f"Authentication failed: incorrect credentials for user {username}.")
        except LDAPSocketOpenError:
            log.error(f"Failed to establish a connection to the LDAP server for user {username}.")
        except LDAPException as e:
            log.error(f"Unexpected error during authentication of {username}: {str(e)}")
        finally:
            if user_connection and user_connection.bound:
                user_connection.unbind()
                log.info("User connection closed after authentication attempt.")

        return False
        
    @ensure_connection
    def get_user_data(self, account_name=None, attributes=None, ou_to_avoid=None, paged_size=50) -> dict:
        """
        Retrieve user data from the LDAP server.
        
        Args:
            account_name (str, optional): Specific account name to search for. Defaults to None.
            attributes (list, optional): List of attributes to retrieve for each user. Defaults to [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES].
            ou_to_avoid (list, optional): List of Organizational Units (OUs) to avoid. Defaults to an empty list.
            paged_size (int, optional): Number of entries to retrieve per page. Defaults to 50.
        
        Returns:
            dict: A dictionary containing the retrieved user data, where the keys are the Common Names (CNs) and the values are the user attributes.
        """
        if attributes is None:
            attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]

        if ou_to_avoid is None:
            ou_to_avoid = []

        users_data = {}
        total_entries = 0
        
        try:
            # Base filter for searching users
            search_filter = '(&(objectClass=user)(!(objectClass=computer)))'
            if account_name:
                search_filter = f"(&{search_filter}(sAMAccountName={account_name}))"

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
                        paged_cookie=cookie
                    )

                    for entry in self.connection.response:
                        if 'dn' in entry:
                            dn = entry['dn']
                            if any(ou in dn for ou in ou_to_avoid):
                                log.info(f"Skipping user in {dn} due to match with OU to avoid.")
                                continue

                            cn = self.extract_cn_from_dn(dn)
                            if cn:
                                mail = entry['attributes'].get('mail', [])
                                if mail:
                                    users_data[cn] = entry['attributes']
                                    total_entries += 1
                                    log.debug(f"User found: {cn}, Attributes: {users_data[cn]}")
                                else:
                                    log.info(f"User {cn} excluded for not having a valid email address.")
                        else:
                            log.warning(f"Entry without 'dn' found: {entry}")
                    
                    # Retrieve cookie for paged search
                    cookie = self.connection.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
                    if not cookie:
                        break

            log.info(f"Total users retrieved: {total_entries}")
            return users_data
        except LDAPException as e:
            log.error(f"Error retrieving users: {str(e)}")
            return {}
            
    def extract_cn_from_dn(self, dn: str) -> str:
        """
        Extract the Common Name (CN) from a Distinguished Name (DN).
        
        Args:
            dn (str): The full Distinguished Name.
        
        Returns:
            str: The value of the CN, or None if not found.
        """
        for component in dn.split(','):
            if component.startswith('CN='):
                return component.split('=')[1]
        return None
    
if __name__ == '__main__':
    # Load environment variables from the .env file
    load_dotenv()

    # LDAP configuration constants
    LDAP_URL = os.getenv('LDAP_URL')  # LDAP server URL
    LDAP_ADMIN_USERNAME = os.getenv('LDAP_ADMIN_USERNAME')  # Administrative user for initial connection
    LDAP_ADMIN_PASSWORD = os.getenv('LDAP_ADMIN_PASSWORD')  # Password for the administrative user
    LDAP_SEARCH_BASES = (lambda x: x.split('|') if x else [])(os.getenv('LDAP_SEARCH_BASES'))  # Initial search bases

    # List of OUs to avoid
    ou_to_avoid = ["OU=Shared Mailboxes"]
    attributes_to_get = ["sAMAccountName", "mail", "whenCreated", "whenChanged"]  # Attributes to retrieve

    ldap_service = UserLdapAuthorizationService(
        ldap_url=LDAP_URL,
        ldap_admin_username=LDAP_ADMIN_USERNAME,
        ldap_admin_password=LDAP_ADMIN_PASSWORD,
        ldap_search_bases=LDAP_SEARCH_BASES
    )

    try:
        ldap_service.test_connection()
        # Test authentication with a valid user
        print(ldap_service.authenticate_user("username without dn", "password"))
        # Test authentication with an invalid user
        print(ldap_service.authenticate_user("invalid_user", "invalid_password"))
        # Retrieve user data for a specific user
        user_data = ldap_service.get_user_data(attributes=attributes_to_get, ou_to_avoid=ou_to_avoid, account_name="jdoe")
        pprint(user_data)
    except ConnectionError as e:
        log.error(f"Connection error: {str(e)}")
    finally:
        ldap_service.close_connection()
