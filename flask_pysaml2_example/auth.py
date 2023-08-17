import requests

from flask import abort, Blueprint, current_app, redirect, request, session, url_for
from flask_login import login_required, login_user, logout_user
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from . import db
from .orm import User


auth_blueprint = Blueprint('auth', __name__)


def load_user(user_id):
    return User.query.filter_by(email=user_id).first()


def saml_client_for(idp_name):
    """
    Given the name of an IdP, return a configuation.
    The configuration is a hash for use by saml2.config.Config
    """
    print('-----------------------------------------')
    print('client_for')
    print('-----------------------------------------')    
    print('IN saml_client_for : %s', idp_name)
    if idp_name not in current_app.config['SAML_IDP_SETTINGS']:
        raise Exception(f'Settings for IDP "{idp_name}" not found on SAML_IDP_SETTINGS.')
    
    
    acs_url = url_for(
        'auth.saml_sso',
        idp_name=idp_name,
        _external=True)
    
    https_acs_url = url_for(
        'auth.saml_sso',
        idp_name=idp_name,
        _external=True,
        _scheme='https')
    print('IN saml_client_for acs_url : %s', acs_url)
    print('IN saml_client_for https_acs_url : %s', https_acs_url)
    
    # SAML metadata changes very rarely. On a production system,
    # this data should be cached as approprate for your production system.
    rv = requests.get(current_app.config['SAML_IDP_SETTINGS'][idp_name]['metadata_url'])
    print('IN saml_client_for rv text : %s', rv.text)

    current_app.logger.debug('rv.rext: %s', rv.text)

    entityid = current_app.config['SAML_IDP_SETTINGS'][idp_name].get('entityid', https_acs_url)
    print('IN saml_client_for entity : %s', entityid)

    settings = {
        'entityid': entityid,
        'metadata': {
            'inline': [rv.text],
        },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        # (acs_url, BINDING_HTTP_REDIRECT),
                        # (acs_url, BINDING_HTTP_POST),
                        (https_acs_url, BINDING_HTTP_REDIRECT),
                        (https_acs_url, BINDING_HTTP_POST)
                    ],
                },
                # Don't verify that the incoming requests originate from us via
                # the built-in cache for authn request ids in pysaml2
                'allow_unsolicited': True,
                # Don't sign authn requests, since signed requests only make
                # sense in a situation where you control both the SP and IdP
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False
            }
        }
    }

    current_app.logger.info('settings: %s', settings)

    saml2_config = Saml2Config()
    saml2_config.load(settings)
    saml2_config.allow_unknown_attributes = True
    
    saml2_client = Saml2Client(config=saml2_config)
    
    return saml2_client


@auth_blueprint.route("/saml/sso/<idp_name>", methods=['GET','POST'])
def saml_sso(idp_name):
    try:
        print('-----------------------------------------')
        print('saml/sso/saml2')
        print('-----------------------------------------')
        print('IN saml_sso: %s', idp_name)

        saml_client = saml_client_for(idp_name)

        current_app.logger.debug('request.form: %s', request.form)

        authn_response = saml_client.parse_authn_request_response(
            request.form['SAMLResponse'],
            BINDING_HTTP_POST
        )
        print('IN saml_sso authn_response: %s', authn_response)

        print(dir(authn_response))
        current_app.logger.info('authn_response: %s', authn_response)
        print('get identity')
        print(authn_response.get_identity())
        subject = authn_response.get_subject()
        user_id = subject.text

        print('SUBJECT')
        print(subject)
        print(user_id)

        redirect_url=url_for('authenticated',user_id=user_id)

        print('IN saml_sso '+redirect_url)
        return redirect(redirect_url)
    except Exception as e:
        current_app.logger.exception('Exception raised during SAML SSO login')
        raise e
        abort(401)


@auth_blueprint.route("/saml/login/<idp_name>", methods=['GET'])
def saml_login(idp_name):
    print('-----------------------------------------')
    print('saml/login/saml2')
    print('-----------------------------------------')

    saml_client = saml_client_for(idp_name)
    reqid, info = saml_client.prepare_for_authenticate()

    current_app.logger.info('reqid: %s', reqid)
    current_app.logger.info('info: %s', info)

    redirect_url = None

    # Select the IdP URL to send the AuthN request to
    _, redirect_url = next(filter(lambda k_v: k_v[0] == 'Location', info['headers']))

    current_app.logger.info('redirect_url: %s', redirect_url)
    print('Redirect *********************************************')
    print(redirect_url)
    print('**************************************************')

    response = redirect(redirect_url, code=302)
    
    # NOTE:
    #   I realize I _technically_ don't need to set Cache-Control or Pragma:
    #     http://stackoverflow.com/a/5494469
    #   However, Section 3.2.3.2 of the SAML spec suggests they are set:
    #     http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
    #   We set those headers here as a "belt and suspenders" approach,
    #   since enterprise environments don't always conform to RFCs
    response.headers['Cache-Control'] = 'no-cache, no-store'
    response.headers['Pragma'] = 'no-cache'
    
    return response


@auth_blueprint.route("/logout")
# @login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
