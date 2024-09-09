### README - LDAP User Authorization Service

This Python script provides a service for managing LDAP user authentication and data retrieval, intended for environments using LDAP for user management and authentication. The `UserLdapAuthorizationService` class allows you to connect to an LDAP server, authenticate users, and retrieve user information.

#### Features

- **Connection Management**: Establishes and maintains a connection to an LDAP server using provided administrative credentials.
- **User Authentication**: Authenticates users by verifying their credentials against the LDAP directory.
- **User Data Retrieval**: Retrieves user attributes from the LDAP directory with support for pagination and filtering based on Organizational Units (OUs) to avoid.
- **Logging**: Logs operations and errors to a file (`ldap_service.log`), including connection attempts, authentication results, and user retrieval activities.

#### Usage

1. **Environment Variables**: Configure the following variables in a `.env` file:
   - `LDAP_URL`: URL of the LDAP server.
   - `LDAP_ADMIN_USERNAME`: Administrative username for initial LDAP connection.
   - `LDAP_ADMIN_PASSWORD`: Password for the administrative user.
   - `LDAP_SEARCH_BASES`: LDAP search bases, separated by `|`.

2. **Initialize and Test**: To run the script, initialize the service with the configured parameters:
   ```python
   ldap_service = UserLdapAuthorizationService(
       ldap_url=LDAP_URL,
       ldap_admin_username=LDAP_ADMIN_USERNAME,
       ldap_admin_password=LDAP_ADMIN_PASSWORD,
       ldap_search_bases=LDAP_SEARCH_BASES
   )
   ldap_service.test_connection()
   ```

3. **Authenticate Users**: Check user credentials against LDAP:
   ```python
   ldap_service.authenticate_user("username", "password")
   ```

4. **Retrieve User Data**: Fetch data for specific users:
   ```python
   user_data = ldap_service.get_user_data(account_name="jdoe", attributes=["sAMAccountName", "mail", "whenCreated"])
   ```

5. **Close Connection**: Clean up by closing the LDAP connection:
   ```python
   ldap_service.close_connection()
   ```

#### Error Handling

The service handles various LDAP exceptions (`LDAPBindError`, `LDAPSocketOpenError`, and general `LDAPException`) and logs errors with detailed messages.

#### Logging

Logs are stored in `ldap_service.log` and include timestamps, log levels, and messages.

#### Requirements

- Python 3.x
- `ldap3` library
- `python-dotenv` library

