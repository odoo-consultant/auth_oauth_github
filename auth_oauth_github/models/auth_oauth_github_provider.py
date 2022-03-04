import logging

from odoo import models, fields

_logger = logging.getLogger(__name__)


class AuthOauthGithubProvider(models.Model):
    _inherit = "auth.oauth.provider"

    github_client_secret = fields.Char(string="Client Secret")
    oauth_github_user_type = fields.Selection([('portal', 'Portal User'),
                                               ('internal', 'Internal User')], default="portal", string='User Type')
    is_oauth_github = fields.Boolean(compute='_compute_is_github_secret_required')

    def _compute_is_github_secret_required(self):
        for rec in self:
            rec.is_oauth_github = rec.auth_endpoint and 'github' in rec.auth_endpoint.lower()
