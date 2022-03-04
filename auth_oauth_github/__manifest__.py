{
    'name': "Odoo Github Authenticator",
    'summary': """
                Integrate Github Authenticator with Odoo.
    """,
    'description': """
                    Github Odoo oauth provider
                    Odoo Github Oauth
                    Odoo github connector
                    Odoo Github integration
                    Github Odoo login
                    Odoo Github authentication
    """,

    'author': "Alex",
    'website': "https://github.com/odoo-consultant",
    'category': 'Authentication',
    'version': '1.0',
    'application': True,
    'license': 'LGPL-3',
    'currency': 'EUR',
    'price': 49.9,
    'maintainer': 'Alex',
    'support': '1069010@qq.com',
    'images': ['static/description/login-page.png'],
    'depends': ['auth_oauth'],
    'data': [
        'data/auth_oauth_github.xml',
        'views/auth_oauth_github_provider_views.xml',
    ]
}
