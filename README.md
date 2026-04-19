# python-ldap-connector

<p>
  <img alt="Python" src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Status" src="https://img.shields.io/badge/status-stable-green">
</p>

> Clase Python reutilizable para autenticar usuarios contra un servidor LDAP y consultar atributos, con paginación, filtrado por OU y logging a archivo.

## Features

- Conexión persistente a un servidor LDAP con credenciales de admin.
- Autenticación de usuarios verificando credenciales contra el directorio.
- Recuperación de atributos (todos, operational, o lista explícita) con paginación y filtro por OUs a excluir.
- Logging detallado a `ldap_service.log` — intentos de conexión, auth y lookups.
- Configuración 100% vía `.env`, sin hardcodes.

## Quickstart

### Requirements

- Python 3.9+
- Acceso a un servidor LDAP (testeado contra OpenLDAP y Active Directory)

### Install

```bash
git clone https://github.com/GDelpo/python-ldap-connector.git
cd python-ldap-connector
python -m venv env
source env/bin/activate          # Linux/macOS
# .\env\Scripts\Activate.ps1     # Windows
pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
# Editar .env con las credenciales de tu servidor LDAP
```

### Run

```bash
python main.py
```

`main.py` incluye un ejemplo de uso con `test_connection()`, autenticación y `get_user_data()`.

## Configuration

| Variable | Descripción |
|----------|-------------|
| `LDAP_URL` | URL del servidor LDAP (ej. `ldap://host:389`) |
| `LDAP_ADMIN_USERNAME` | DN o username admin para el bind inicial |
| `LDAP_ADMIN_PASSWORD` | Password del admin |
| `LDAP_SEARCH_BASES` | Bases de búsqueda (DN); múltiples separadas por `\|` |

## Usage

```python
from main import UserLdapAuthorizationService

ldap = UserLdapAuthorizationService(
    ldap_url=LDAP_URL,
    ldap_admin_username=LDAP_ADMIN_USERNAME,
    ldap_admin_password=LDAP_ADMIN_PASSWORD,
    ldap_search_bases=LDAP_SEARCH_BASES,
)

ldap.test_connection()
ldap.authenticate_user("username", "password")
data = ldap.get_user_data(
    account_name="jdoe",
    attributes=["sAMAccountName", "mail", "whenCreated"],
)
```

El archivo `example_persona_all_attrs.txt` muestra la forma típica de los atributos retornados por un AD (datos de ejemplo).

## Architecture

```
python-ldap-connector/
├── main.py                          # UserLdapAuthorizationService + demo CLI
├── example_persona_all_attrs.txt    # Ejemplo de atributos retornados
├── requirements.txt
├── .env.example
└── LICENSE
```

Librería subyacente: [`ldap3`](https://ldap3.readthedocs.io/).

## License

[MIT](LICENSE) © 2026 Guido Delponte
