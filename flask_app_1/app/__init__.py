import os
import json
import logging
import requests
from flask import Flask, jsonify, request, render_template, redirect, make_response
from flask_cors import CORS
from flask_oidc import OpenIDConnect
from sqlitedict import SqliteDict

app = Flask(__name__)
CORS(app)
app.config.update({
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': '/flask_app/client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': os.getenv('REALM'),
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})
oidc = OpenIDConnect(app, credentials_store=SqliteDict('users.db', autocommit=True))

@app.route('/', methods=['GET'])
def index():
    if oidc.user_loggedin:
        display_name = oidc.user_getfield('given_name') + ' ' + oidc.user_getfield('family_name')
        return render_template('index.html', user_logged_in=True, user=display_name)
    else:
        return render_template('index.html', user_logged_in=False)


@app.route('/login', methods=['GET'])
@oidc.require_login
def login():
    return redirect('/')

@app.route('/profile', methods=['GET'])
@oidc.accept_token()
def profile():
    user_id = oidc.user_getfield('sub')
    if user_id in oidc.credentials_store:
        return oidc.credentials_store[user_id]
    return 'Data not available'

@app.route('/logout')
@oidc.require_login
def logout():
    """Performs local logout by removing the session cookie."""
    user_id = oidc.user_getfield('sub')
    db = SqliteDict('users.db')
    del_item = 'DELETE FROM "%s" WHERE key = ?' % db.tablename 
    db.conn.execute(del_item, (user_id,)) 
    db.commit()
    oidc.logout()
    res = make_response('<h1>You have successfully Logged out, click to <a href="/">Home</a></h1>')
    res.set_cookie('session', '', expires=0)
    return res