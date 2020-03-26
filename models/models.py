import re
import jwt
from flask_sqlalchemy import SQLAlchemy
from flask import request, jsonify, json
from functools import wraps
from app import app

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    reset_token = db.Column(db.String())

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

def get_JSON(jsonFile):
    with open(jsonFile, 'r') as jf:
        return json.load(jf)
json_messages = get_JSON('./json/messages.json')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : json_messages.get("token_expired", "")}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : json_messages.get("token_incorrect", "")}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def check_login(email, password):
    regex = r'^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
    if (not re.search(regex, email)) or (len(password) < 6):
        return True