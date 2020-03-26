import sys
sys.path.append("./")
from app import app

import requests
from requests.auth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

from config.config import *

from app import User
exemplary_user = User.query.filter_by(id='2').first()
del_exemplary_user = User.query.filter_by(id='3').first()

from faker import Factory

faker = Factory.create()
faker_email = faker.email()
faker_password = generate_password_hash(faker.word(), method='sha256')

def get_auth_admin_token():
    username = "admin@admin.pl"
    password = "12345"
    response = requests.get(
        'http://127.0.0.1:5000/login',
        auth=HTTPBasicAuth(username, password)
    )
    data = response.json()
    return data.get('token')

def test_create_admin():
    auth_admin_token = get_auth_admin_token()
    response = requests.post(
        'http://127.0.0.1:5000/admin',
        headers={'x-access-token': auth_admin_token},
        json={'email': faker_email, 'password': faker_password, 'admin': 'True'}
    )
    assert response.status_code == 200

def test_get_all_users():
    auth_admin_token = get_auth_admin_token()
    response = requests.get(
        'http://127.0.0.1:5000/user',
        headers={'x-access-token': auth_admin_token}
    )
    assert response.status_code == 200

def test_status_code_get_one_user():
    auth_admin_token = get_auth_admin_token()
    response = requests.get(
        'http://127.0.0.1:5000/user/exemplary_user.public_id',
        headers={'x-access-token': auth_admin_token}
    )
    assert response.status_code == 200

def test_data_get_email_get_one_user():
    auth_admin_token = get_auth_admin_token()
    response = requests.get(
        'http://127.0.0.1:5000/user/' + str(exemplary_user.public_id),
        headers={'x-access-token': auth_admin_token}
    )
    data = response.json()
    assert data.get('user')['email'] == exemplary_user.email

def test_create_user():
    auth_admin_token = get_auth_admin_token()
    response = requests.post(
        'http://127.0.0.1:5000/user',
        headers={'x-access-token': auth_admin_token},
        json={'email': faker_email, 'password': faker_password}
    )
    assert response.status_code == 200

def test_promote_user():
    auth_admin_token = get_auth_admin_token()
    response = requests.put(
        'http://127.0.0.1:5000/user/' + str(exemplary_user.public_id),
        headers={'x-access-token': auth_admin_token},
        data = {'admin': 'True'}
    )
    assert response.status_code == 200

def test_delete_user():
    auth_admin_token = get_auth_admin_token()
    response = requests.delete(
        'http://127.0.0.1:5000/user/' + str(del_exemplary_user.public_id),
        headers={'x-access-token': auth_admin_token}
    )
    assert response.status_code == 200

def test_login():
    response = requests.get(
        'http://127.0.0.1:5000/login',
        auth=HTTPBasicAuth(faker_email, faker_password)
    )
    assert response.status_code == 200