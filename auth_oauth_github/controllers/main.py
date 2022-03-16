import base64
import json
import logging

import requests
import ssl
import urllib.request
import werkzeug

from odoo import http, api, SUPERUSER_ID, _
from odoo import registry as registry_get
from odoo.addons.auth_oauth.controllers.main import OAuthLogin, OAuthController, fragment_to_query_string
from odoo.addons.web.controllers.main import set_cookie_and_redirect, login_and_redirect, ensure_db
from odoo.exceptions import AccessDenied
from odoo.http import request
from werkzeug.exceptions import BadRequest

_logger = logging.getLogger(__name__)


user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36'
urllib_headers = {'User-Agent': user_agent}


def fetch_image_from_url(url):
    if not url:
        return None
    try:
        context = ssl._create_unverified_context()

        req = urllib.request.Request(url, headers=urllib_headers)
        response = urllib.request.urlopen(req, context=context)
        data = response.read()
        response.close()
        return data
    except Exception as e:
        _logger.error(e)
        # pass

    return None


class OAuthGithubLogin(OAuthLogin):
    def list_providers(self):
        providers = super(OAuthGithubLogin, self).list_providers()
        for provider in providers:
            if provider.get('name', '').lower() in ('github',):
                state = self.get_state(provider)
                params = dict(
                    client_id=provider['client_id'],
                    scope=provider['scope'],
                    state=json.dumps(state),
                )
                provider['auth_link'] = "%s?%s" % (provider['auth_endpoint'], werkzeug.urls.url_encode(params))
        return providers

    @http.route()
    def web_login(self, *args, **kw):
        # TODO: duplicated code
        ensure_db()
        if request.httprequest.method == 'GET' and request.session.uid and request.params.get('redirect'):
            # Redirect if already logged in and redirect param is present
            return request.redirect(request.params.get('redirect'))

        response = super(OAuthGithubLogin, self).web_login(*args, **kw)
        if request.params.get('oauth_error') and response.is_qweb and not response.qcontext.get('error'):
            error = request.params.get('oauth_error')
            # 1-3 already handled in OAuthLogin
            if error == '4':
                error = _("Invalid endpoint configuration, please contact your Administrator")
            elif error == '5':
                error = _("Github oauth calling failed, please contact Administrator")
            elif error == '6':
                error = _("Invalid system configuration, please contact Administrator")
            else:
                error = None

            if error:
                response.qcontext['error'] = error

        return response


class OAuthGithubController(OAuthController):

    @http.route('/auth_oauth/github/signin', type='http', auth='none')
    @fragment_to_query_string
    def github_signin(self, **kw):
        state = json.loads(kw['state'])
        dbname = state['d']
        if not http.db_filter([dbname]):
            return BadRequest()

        user_data = json.loads((kw['user_data']))
        provider = state['p']
        context = state.get('c', {})
        registry = registry_get(dbname)

        avatar = fetch_image_from_url(user_data.get('avatar_url'))
        avatar_base64 = base64.b64encode(avatar) if avatar else None

        with registry.cursor() as cr:
            try:
                env = api.Environment(cr, SUPERUSER_ID, context)
                validation = {
                    'user_id': user_data.get('github_id'),
                    # 'email': user_data.get('email') or user_data.get('username'),
                    'name': user_data.get('github_name') or user_data.get("username"),
                }
                if user_data.get('email'):
                    validation.update({'email': user_data.get('email')})

                login = env['res.users'].sudo()._auth_oauth_signin(provider, validation, kw)
                # save avatar
                if avatar_base64:
                    user = env['res.users'].sudo().search([('login', '=', login)])
                    user.write({'image_1920': avatar_base64})
                cr.commit()
                credentials = (request.env.cr.dbname, login, kw.get('access_token'))
                action = state.get('a')
                menu = state.get('m')
                redirect = werkzeug.urls.url_unquote_plus(state['r']) if state.get('r') else False
                url = '/web'
                if redirect:
                    url = redirect
                elif action:
                    url = '/web#action=%s' % action
                elif menu:
                    url = '/web#menu_id=%s' % menu
                resp = login_and_redirect(*credentials, redirect_url=url)
                # Since /web is hardcoded, verify user has right to land on it
                return resp
            except AttributeError:
                # auth_signup is not installed
                _logger.error("auth_signup not installed on database %s: oauth sign up cancelled." % (dbname,))
                url = "/web/login?oauth_error=1"
            except AccessDenied:
                # oauth credentials not valid, user could be on a temporary session
                _logger.info(
                    'OAuth2: access denied, redirect to main page in case a valid session exists, without setting cookies')
                url_303 = "/web/login?oauth_error=3"
                redirect = werkzeug.utils.redirect(url_303, 303)
                redirect.autocorrect_location_header = False
                return redirect
            except Exception as e:
                # signup error
                _logger.exception("OAuth2: %s" % str(e))
                url = "/web/login?oauth_error=2"

        return set_cookie_and_redirect(url)

    @http.route(['/oauth/github/token'], auth='public', csrf=False, methods=['GET', 'POST'], type='http')
    def get_github_oauth_token(self, **post):
        if post.get('state'):
            provider = request.env['auth.oauth.provider'].sudo().browse(json.loads(post.get('state')).get('p'))
        else:
            provider = request.env.ref('auth_oauth_github.provider_github')
            provider = request.env[provider._name].sudo().browse(provider.id)

        client_id = provider.client_id
        client_secret = provider.github_client_secret
        if not all((client_id, client_secret, provider.validation_endpoint, provider.data_endpoint)):
            url_303 = "/web/login?oauth_error=6"
            redirect = werkzeug.utils.redirect(url_303, 303)
            redirect.autocorrect_location_header = False
            return redirect

        if not post.get("code"):
            url_303 = "/web/login?oauth_error=5"
            redirect = werkzeug.utils.redirect(url_303, 303)
            redirect.autocorrect_location_header = False
            return redirect

        params = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": post.get("code")
        }

        response = requests.post(provider.validation_endpoint, json=params)
        if response.status_code not in (200, 201) or response.reason != 'OK':
            url_303 = "/web/login?oauth_error=5"
            _logger.info(
                'OAuth2: Access denied, redirect to main page in case a valid session exists, without setting cookies. REASON :- %s' % str(
                    response_data[0]))
            redirect = werkzeug.utils.redirect(url_303, 303)
            redirect.autocorrect_location_header = False
            return redirect

        response_data = response.content.decode("UTF-8").split('&')
        if 'error=' in response_data or 'error=' in response_data[0]:
            url_303 = "/web/login?oauth_error=5"
            _logger.info(
                'OAuth2: access denied, redirect to main page in case a valid session exists, without setting cookies. REASON :- %s'% str(
                response_data[0]))
            redirect = werkzeug.utils.redirect(url_303, 303)
            redirect.autocorrect_location_header = False
            return redirect

        access_token = response_data[0].split('=')[1]
        # 'https://api.github.com/user'
        user_data = requests.get(provider.data_endpoint, auth=('', access_token)).json()
        params = {
            'username': user_data.get('login'),
            'github_id': user_data.get('id'),
            'github_name': user_data.get('name'),
            'email': user_data.get('email'),
            'avatar_url': user_data.get('avatar_url'),
        }

        redirect_url = request.httprequest.url_root + "auth_oauth/github/signin"
        redirect_url = redirect_url + '?access_token=%s&state=%s&user_data=%s&provider=%s' % (
            access_token, post.get('state'), json.dumps(params), provider.id)
        return werkzeug.utils.redirect(redirect_url)
