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
    'ENABLE_TEMPLATE_PROCESSING': True
}

APP_ICON = '/static/assets/images/plandoc-custom/logo_bi.svg'
FAVICONS = [{'href': '/static/assets/images/plandoc-custom/favicon.ico'}]

LANGUAGES = {
    "en": {"flag": "us", "name": "English"},
    "hu": {"flag": "hu", "name": "Hungarian"}
}

TALISMAN_CONFIG = {
    "content_security_policy": {
        "base-uri": ["'self'"],
        "default-src": ["'self'"],
        "img-src": [
            "'self'",
            "blob:",
            "data:",
            "https://apachesuperset.gateway.scarf.sh",
            "https://static.scarf.sh/",
            # "https://avatars.slack-edge.com", # Uncomment when SLACK_ENABLE_AVATARS is True
        ],
        "worker-src": ["'self'", "blob:"],
        "connect-src": [
            "'self'",
            "https://api.mapbox.com",
            "https://events.mapbox.com",
        ],
        "object-src": "'none'",
        "style-src": [
            "'self'",
            "'unsafe-inline'",
        ],
        "script-src": ["'self'", "'strict-dynamic'", "'unsafe-eval'"],
    },
    "content_security_policy_nonce_in": ["script-src"],
    "force_https": False,
    "session_cookie_secure": False,
}
