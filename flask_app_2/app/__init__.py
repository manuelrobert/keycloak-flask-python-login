import logging
import sys
import requests
import json
import os
import urllib.parse

from dotenv import load_dotenv
from flask import Flask, render_template, url_for, redirect, session, g
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from functools import wraps 

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
CORS(app)
oauth = OAuth(app)

base_url = os.getenv('API_BASE_URL') + '/realms/' + os.getenv('REALM')

keyclaok = oauth.register(
    name='keycloak',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    server_metadata_url=f'{base_url}/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = dict(session).get('user', None)
        if user:
            g.user = user
            keycloak_user = check_user_by_token(user.get('access_token', None))
            if keycloak_user.status_code == 401:
                return redirect('/login')
            has_roles = check_roles(user.get('access_token', None))
            if not has_roles:
                logout_user(access_token, refresh_token, client_id)
            return f(*args, **kwargs)
        else:
            return redirect('/login')
    return decorated_function

@app.route('/')
def index():
    user_data = dict(session).get('user', None)
    if user_data:
        access_token = user_data.get('access_token', None)
        has_roles = check_roles(access_token)
        if not has_roles:
            return 'No Role'
        
        profile = user_data['userinfo']
        return render_template('index.html', user_logged_in=True, user=profile.get('name', None))
    else:
        return render_template('index.html', user_logged_in=False)

@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    user_data = oauth.keycloak.authorize_access_token()
    access_token = user_data.get('access_token', None)
    refresh_token = user_data.get('refresh_token', None)
    client_id = user_data['userinfo'].get('azp', None)
    has_roles = check_roles(access_token)
    if has_roles:
        session['user'] = user_data
        session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
        return redirect('/')
    else:
        logout_user(access_token, refresh_token, client_id)
        return 'No Role'

@app.route('/logout')
@login_required
def logout():
    user_data = dict(session).get('user', None)
    if user_data:
        access_token = user_data.get('access_token', None)
        refresh_token = user_data.get('refresh_token', None)
        user_info = user_data.get('userinfo')
        client_id = user_info.get('azp', None)
        resp = logout_user(access_token, refresh_token, client_id)
        print(resp)

        for key in list(session.keys()):
            print(key)
            session.pop(key)

    return redirect('/')

def check_user_by_token(access_token):
    url = f'{base_url}/protocol/openid-connect/userinfo'
    headers = {'Authorization': 'Bearer %s' % (access_token), 'Accept': 'application/json'}
    return requests.get(url, headers=headers)

def check_roles(access_token):
    result = check_user_by_token(access_token).text
    roles = json.loads(result).get('roles', None)
    if os.getenv('ROLE') in roles:
        return True
    return False

def logout_user(access_token, refresh_token, client_id):
    encoded_redirect_uri = urllib.parse.quote(os.getenv('REDIRECT_URI').encode('utf8'))
    headers = {'Authorization': 'Bearer %s' % (access_token)}
    data = {'client_id': client_id, 'client_secret': os.getenv('CLIENT_SECRET'), 'refresh_token': refresh_token}
    # url=f'{base_url}/protocol/openid-connect/logout'

    url=f'{base_url}/protocol/openid-connect/logout?redirect_uri={encoded_redirect_uri}'
    print(url)
    resp = requests.post(url, data=data, headers=headers)
    return resp.status_code


@app.route('/api')
@login_required
def api():
    access_token = g.user.get('access_token', None)
    refresh_token = g.user.get('refresh_token', None)
    client_id = g.user['userinfo'].get('azp', None)
    print(access_token)
    print('\n')
    print(refresh_token)
    headers = {'Authorization': 'Bearer %s' % (access_token), 'Accept': 'application/json'}
    data = {'client_id': client_id, 'client_secret': os.getenv('CLIENT_SECRET'), 'refresh_token': refresh_token}
    userInfoEndpoint = f'{base_url}/protocol/openid-connect/userinfo'
    userInfoResponse = requests.get(userInfoEndpoint, headers=headers)
    print(userInfoResponse.status_code)
    return userInfoResponse.text, 200