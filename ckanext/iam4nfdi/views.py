from functools import wraps
from logging import getLogger

import ckan.lib.helpers as h
import ckan.model as model
import ckan.plugins.toolkit as toolkit
from ckan.common import g
from ckan.lib import base
from ckan.views.user import me
from ckanext.iam4nfdi.oauth2 import OAuth2Controller
from flask import Blueprint, request, session

log = getLogger(__name__)
oauth2_helper = OAuth2Controller()


def inject_request(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(request, *args, **kwargs)

    return wrapper


@inject_request
def redirect_response(request_, user_found=True):
    next_ = request_.args.get('next', request_.args.get('came_from'))
    if not user_found:
        resp = h.helper_functions.redirect_to(h.url_for('iam4nfdi.organization_selection'))
    elif next_ and h.url_is_local(next_):
        resp = h.helper_functions.redirect_to(next_)
    else:
        resp = me()
    return resp


def _user_organizations():
    """
    Get all organization memberships of the current user.
    Returns a list with the names of the organizations.
    """
    q = model.Session.query(model.Member, model.Group) \
        .filter(model.Member.table_name == 'user') \
        .filter(model.Member.table_id == model.User.get(toolkit.c.user).id) \
        .filter(model.Member.state == 'active') \
        .join(model.Group) \
        .filter(model.Group.is_organization == True) \
        .filter(model.Group.state == 'active')

    q_res = q.all()
    user_orgs = []
    for res in q_res:
        user_orgs.append(res[1].name)

    return user_orgs


def organization_selection():
    if not toolkit.c.user:
        base.abort(403, toolkit._('Need to be logged in to select an organization.'))

    context = {'model': model, 'session': model.Session, 'user': 'guest'}

    organization_ids = toolkit.get_action('organization_list')(context, {})
    organizations = []
    data_dict = {
        'include_dataset_count': False,
        'include_extras': False,
        'include_users': False,
        'include_groups': False,
        'include_tags': False,
        'include_followers': False
    }
    for oid in organization_ids:
        data_dict['id'] = oid
        org_data = toolkit.get_action('organization_show')(context, data_dict)
        if org_data['state'] == 'active':
            organizations.append({
                'name': org_data['display_name'],
                'id': oid
            })

    return toolkit.render('organization_selection.html',
                          extra_vars={
                              'organizations': organizations,
                              'user_orgs': _user_organizations()
                          })


def organization_selection_post():
    if not toolkit.c.user:
        base.abort(403, toolkit._('Need to be logged in to select an organization.'))

    orgs_selected = set(request.form.getlist('items'))

    context = {
        'model': model,
        'user': toolkit.c.user,
        'ignore_auth': True
    }

    data_dict = {
        'object': toolkit.c.user,
        'object_type': 'user',
        'capacity': 'editor'
    }

    user_orgs = set(_user_organizations())
    to_delete = user_orgs - orgs_selected
    to_add = orgs_selected - user_orgs

    for org in to_add:
        data_dict['id'] = org
        toolkit.get_action('member_create')(context, data_dict)

    for org in to_delete:
        data_dict['id'] = org
        toolkit.get_action('member_delete')(context, data_dict)

    toolkit.h.flash_success('Your organization memberships have been updated successfully.')
    return redirect_response()


def oauth2_login(profile_name):
    remote_app = oauth2_helper.get_remote_app(profile_name)
    log.debug('PF: ' + profile_name)
    log.debug('remote_app:' + str(remote_app))

    if remote_app is None:
        extra_vars = {'error_summary': 'Error accessing remote app: ' + profile_name}
        return base.render('error_page.html', extra_vars=extra_vars)

    if g.user:  # Check if already logged in
        return redirect_response()

    redirect_uri = oauth2_helper.get_callback_url(profile_name)
    return remote_app.authorize_redirect(redirect_uri)


def oauth2_callback(profile_name):
    remote_app = oauth2_helper.get_remote_app(profile_name)
    if remote_app is None:
        extra_vars = {'error_summary': 'Error accessing remote app: ' + profile_name}
        return base.render('error_page.html', extra_vars=extra_vars)

    token = remote_app.authorize_access_token()
    if token is None or token.get('access_token') is None:
        error_summary = 'Access denied: reason=%s error=%s' % (
            request.args.get('error', 'Unknown'),
            request.args.get('error_description', 'Unknown')
        )
        return base.render('error_page.html', extra_vars={'error_summary': error_summary})

    # Store token in session
    session[profile_name + '_token'] = token

    try:
        # Get user info from OAuth provider
        # user_data = remote_app.get('user').data
        user_data = remote_app.userinfo(token=token)
        log.debug('User data from OAuth provider: %s', user_data)

        # Convert user data to CKAN user dict
        user_dict = oauth2_helper.convert_user_data_to_ckan_user_dict(profile_name, user_data)
        log.debug('Converted user dict: %s', user_dict)

        # Check if user exists
        context = {'ignore_auth': True, 'model': model, 'session': model.Session}
        user_found = True
        try:
            user = toolkit.get_action('user_show')(context, {'id': user_dict['name']})
            log.info('Existing user found: %s', user['name'])
        except toolkit.ObjectNotFound:
            # Create the user
            user_found = False
            log.info('Creating new user: %s', user_dict['name'])
            user = toolkit.get_action('user_create')(context, user_dict)

        # Redirect
        userobj = model.User.by_name(user['name'])
        resp = redirect_response(user_found=user_found)
        if userobj:
            if toolkit.check_ckan_version(min_version='2.10'):
                from ckan.common import login_user
                login_user(userobj)
            else:
                from ckan.views.user import set_repoze_user
                set_repoze_user(user['name'], resp)
        return resp

    except Exception as e:
        log.error('Error in OAuth callback: %s', str(e), exc_info=True)
        extra_vars = {'error_summary': 'Error processing OAuth callback: ' + str(e)}
        return base.render('error_page.html', extra_vars=extra_vars)


def oauth2_logout(profile_name):
    if profile_name + '_token' in session:
        del session[profile_name + '_token']
    return toolkit.redirect_to('user.logout')


blueprint = Blueprint('iam4nfdi', __name__)
blueprint.template_folder = u'templates'

blueprint.add_url_rule(u'/oauth2/login/<profile_name>', view_func=oauth2_login)
blueprint.add_url_rule(u'/oauth2/callback/<profile_name>', view_func=oauth2_callback)
blueprint.add_url_rule(u'/oauth2/logout/<profile_name>', view_func=oauth2_logout)
blueprint.add_url_rule(u'/organization_selection', view_func=organization_selection, methods=['GET'])
blueprint.add_url_rule(u'/organization_selection', view_func=organization_selection_post, methods=['POST'])


def get_blueprints():
    return [blueprint]
