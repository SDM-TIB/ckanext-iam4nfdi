import logging

import flask
import ckan.lib.helpers as h
from authlib.integrations.flask_client import OAuth
import secrets
import string
import re
import os

log = logging.getLogger(__name__)


class OAuth2Controller:
    def __init__(self):
        self.oauth = OAuth(flask.current_app)
        self._profiles = None

    @property
    def profiles(self):
        if self._profiles is None:
            self._profiles = self._get_oauth2_profiles()
        return self._profiles

    def _get_oauth2_profiles(self):
        profiles = {}

        # RegApp
        regapp_profile = {
            'client_id': os.environ.get('CKANEXT__IAM4NFDI__CLIENT_ID', None),
            'client_secret': os.environ.get('CKANEXT__IAM4NFDI__CLIENT_SECRET', None),
            'server_metadata_url': 'https://regapp.nfdi-aai.de/oidc/realms/nfdi/.well-known/openid-configuration',
            'client_kwargs': {
                'scope': 'openid profile email',
            }
        }
        profiles['regapp'] = regapp_profile

        regapp_remote_app = self.oauth.register('regapp', **regapp_profile)

        site_url = h.url_for('home.index', _external=True)
        profiles['regapp']['remote_app'] = regapp_remote_app
        profiles['regapp']['callback_url'] = site_url + 'oauth2/callback/regapp'
        log.debug('Callback URL: ' + site_url + 'oauth2/callback/regapp')

        return profiles

    def get_remote_app(self, profile_name):
        return self.profiles.get(profile_name, {}).get('remote_app')

    def get_callback_url(self, profile_name):
        return self.profiles.get(profile_name, {}).get('callback_url', '')

    def convert_user_data_to_ckan_user_dict(self, profile_name, user_data):
        if profile_name == 'regapp':
            return self._regapp_convert_user_data_to_ckan_dict(user_data)
        # Add other profile conversions here if needed
        return {}

    def _regapp_convert_user_data_to_ckan_dict(self, regapp_user_data):
        # Generate a valid CKAN username
        username = self._generate_valid_username(regapp_user_data["voperson_id"])

        user_dict = {
            "name": username,
            "fullname": regapp_user_data["name"],
            "email": regapp_user_data["email"],
            "password": self._generate_password()
        }

        return user_dict

    def _generate_valid_username(self, original_username):
        # Convert to lowercase and replace invalid characters with underscores
        valid_username = re.sub(r'[^a-z0-9_-]', '_', original_username.lower())
        
        # Ensure the username starts with a letter
        if not valid_username[0].isalpha():
            valid_username = 'user_' + valid_username

        # Truncate if longer than 100 characters (CKAN's limit)
        if len(valid_username) > 100:
            valid_username = valid_username[:100]

        return valid_username

    def _generate_password(self, length=16):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        return password
