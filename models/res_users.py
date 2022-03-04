import logging

import requests
import werkzeug
from odoo import models, fields, api, _
from odoo.addons.auth_signup.models.res_partner import SignupError
from odoo.tools.misc import ustr

_logger = logging.getLogger(__name__)


class ResUser(models.Model):
    _inherit = 'res.users'

    @api.model
    def _signup_create_user(self, values):
        """ signup a new user using the template user """

        # check that uninvited users may sign up
        provider = self.env.ref('auth_oauth_github.provider_github')
        if provider.id == values.get('oauth_provider_id') and provider.oauth_github_user_type == 'internal':
            if 'partner_id' not in values and self._get_signup_invitation_scope() != 'b2c':
                raise SignupError(_('Signup: signup is not allowed for uninvited users'))
            return self._create_internal_user_from_default_template(values)
        else:
            return super(ResUser, self)._signup_create_user(values)

    def _create_internal_user_from_default_template(self, values):
        if not values.get('login'):
            raise ValueError(_('Signup: no login given for new user'))
        if not values.get('partner_id') and not values.get('name'):
            raise ValueError(_('Signup: no name or partner given for new user'))

        template_user = self.env.ref('base.default_user')
        if not template_user.exists():
            raise ValueError(_('Signup: invalid template user'))

        values['active'] = True
        try:
            with self.env.cr.savepoint():
                return template_user.with_context(no_reset_password=True).copy(values)
        except Exception as e:
            # copy may failed if asked login is not available.
            raise SignupError(ustr(e))
