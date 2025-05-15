import ckan.model as model
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckanext.iam4nfdi.views as views
from ckan.common import g
from flask import session


class IAM4nfdi(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'iam4nfdi')

    # IBlueprint
    def get_blueprint(self):
        return views.get_blueprints()

    # IAuthenticator
    def identify(self):
        user = getattr(g, 'user', None)
        if user:
            if not isinstance(user, model.User):
                user = model.User.by_name(user)
            g.user = user
            g.userobj = user

    def login(self):  # This method is called when the login button is clicked
        pass

    def logout(self):
        for profile_name in views.oauth2_helper.profiles:
            if profile_name + '_token' in session:
                del session[profile_name + '_token']
        g.user = None
        g.userobj = None
