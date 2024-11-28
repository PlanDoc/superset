from flask_appbuilder.security.manager import AUTH_OID
from superset.security import SupersetSecurityManager
from flask_oidc import OpenIDConnect
from flask_appbuilder.security.views import AuthOIDView
from flask_login import login_user
from urllib.parse import quote
from flask_appbuilder.views import ModelView, SimpleFormView, expose
from flask import (
    redirect,
    request
)
import logging
from flask import session

AUTH_ROLES_MAPPING = {
  "bi-admin": "Admin"
}
SUPERSET_BASE_ROLES = ['Admin', 'Public', 'Alpha', 'Gamma', 'sql_lab', 'customer']
SUPERSET_ADMIN_ROLE = 'Admin'
SUPERSET_BASE_ROLE = 'customer'
KEYCLOAK_BASE_ROLES = ['default-roles-plandoc-bi', 'offline_access', 'uma_authorization']

class OIDCSecurityManager(SupersetSecurityManager):

    def __init__(self, appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
            self.oid = OpenIDConnect(self.appbuilder.get_app)
        self.authoidview = AuthOIDCView

class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):
        sm = self.appbuilder.sm
        oidc = sm.oid

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield('email'))
            info = oidc.user_getinfo(['role_keys'])

            final_roles = []

            for role in info.get('groups'):
                if role not in KEYCLOAK_BASE_ROLES:
                    for keycloak_role in AUTH_ROLES_MAPPING:
                        if role == keycloak_role:
                            role = AUTH_ROLES_MAPPING[keycloak_role]
                    final_roles.append(role)

            if len(final_roles) == 0:
                final_roles = [SUPERSET_BASE_ROLE]

            particular_superset_roles = []

            for final_role in final_roles:
                if final_role not in SUPERSET_BASE_ROLES:
                    particular_superset_roles.append(final_role)

            superset_all_roles = {r.name for r in sm.get_all_roles()}
            
            if 'customer' not in superset_all_roles:
                sm.add_role('customer')

            for particular_role in particular_superset_roles:
                if particular_role not in superset_all_roles:
                    sm.copy_role('customer', particular_role)

            if user is None:
                info = oidc.user_getinfo(['preferred_username', 'given_name', 'family_name', 'email'])
                user = sm.add_user(info.get('preferred_username'), info.get('given_name'), info.get('family_name'),
                                   info.get('email'), sm.find_role(final_roles[0]))
                if len(final_roles) > 1:
                    for i in range(0, len(final_roles)):
                        user.roles.append(sm.find_role(final_roles[i]))
                    sm.update_user(user)
            else:
                info = oidc.user_getinfo(['given_name', 'family_name'])
                
                user_roles = {r.name for r in user.roles}

                new_roles = set(final_roles) - user_roles
                removed_roles = user_roles - set(final_roles)

                for role in new_roles:
                    user.roles.append(sm.find_role(role))

                for role in removed_roles:
                    user.roles.remove(sm.find_role(role))
                    
                user.first_name = info.get('given_name')
                user.last_name = info.get('family_name')
                
                sm.update_user(user)

            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        oidc = self.appbuilder.sm.oid

        if 'oidc_auth_token' in session:
            redirect_url = request.url_root.strip('/') + self.appbuilder.get_url_for_login
            url = oidc.client_secrets.get('issuer') + '/protocol/openid-connect/logout?post_logout_redirect_uri=' + quote(redirect_url) + '&id_token_hint=' + str(session.get('oidc_auth_token')['id_token'])
        else:
            url = oidc.client_secrets.get('issuer') + '/protocol/openid-connect/logout'

        oidc.logout()
        super(AuthOIDCView, self).logout()

        session.clear()
        return redirect(url)
