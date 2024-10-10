from keycloak_security_manager import OIDCSecurityManager
from flask_appbuilder.security.manager import AUTH_OID, AUTH_REMOTE_USER, AUTH_DB, AUTH_LDAP, AUTH_OAUTH
import os

DATABASE_DIALECT = os.getenv("DATABASE_DIALECT")
DATABASE_USER = os.getenv("DATABASE_USER")
DATABASE_PASSWORD = open(os.getenv("DATABASE_PASSWORD"), 'r').read()
DATABASE_HOST = os.getenv("DATABASE_HOST")
DATABASE_PORT = os.getenv("DATABASE_PORT")
DATABASE_DB = os.getenv("DATABASE_DB")
SQLALCHEMY_DATABASE_URI = (
    f"{DATABASE_DIALECT}://"
    f"{DATABASE_USER}:{DATABASE_PASSWORD}@"
    f"{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_DB}"
)

SECRET_KEY = open(os.getenv('SECRET_KEY'), 'r').read()

ENABLE_PROXY_FIX = True

AUTH_TYPE = AUTH_OID

CUSTOM_SECURITY_MANAGER = OIDCSecurityManager

OIDC_CLIENT_SECRETS = os.environ['OIDC_CLIENT_SECRETS']
OIDC_OPENID_REALM = open(os.getenv('OIDC_OPENID_REALM'), 'r').read()
OIDC_INTROSPECTION_AUTH_METHOD = 'client_secret_post'

FEATURE_FLAGS = {
    'DASHBOARD_RBAC': True,
}

APP_ICON = '/static/assets/images/plandoc-custom/logo_bi.svg'
FAVICONS = [{'href': '/static/assets/images/plandoc-custom/favicon.ico'}]
