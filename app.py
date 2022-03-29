#!/usr/bin/env python

from flask import Flask, jsonify, make_response, request
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from dotenv import load_dotenv

import uuid
import jwt
import datetime
import os

# load env vars from .env file
load_dotenv()

SECRET_KEY = str(os.getenv('MTAA_SECRET_KEY'))
DB_HOST = str(os.getenv('MTAA_DB_HOST'))
DB_USER = str(os.getenv('MTAA_DB_USER'))
DB_PASS = str(os.getenv('MTAA_DB_PASS'))
DB_NAME = str(os.getenv('MTAA_DB_NAME'))

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_NAME}:{DB_PASS}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(255))
    password = db.Column(db.String(255))
    username = db.Column(db.String(255))
    email = db.Column(db.String(255))
    profile_picture = db.Column(db.String(255))


class Reviews(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)


class Companies(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    description = db.Column(db.Text)
    vat_number = db.Column(db.String(10))
    profile_picture = db.Column(db.String(255))


class Follows(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)


def jwt_token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None

        token_header = 'X-Access-Token'

        if token_header in request.headers:
            token = request.headers[token_header]

        if not token:
            return jsonify({'message': 'Valid Auth token is required!'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Invalid Auth token!'})

        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    user = Users(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, email=data['email'])

    db.session.add(user)
    db.session.commit()

    return jsonify({'message': f'User {data["username"]} created successfully!'})


@app.route('/login', methods=['POST'])
def login_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('User could not be verified!', 401, {'Authentication': 'Login required'})

    user = Users.query.filter_by(username=auth.username).first()

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)},
            app.config['SECRET_KEY'], "HS256")

        return jsonify({'token': token})

    return make_response('User could not be verified!', 401, {'Authentication': 'Login required'})


@app.route('/')
def hello_world():  # put application's code here
    print(app.config['SQLALCHEMY_DATABASE_URI'])
    print(app.config['SECRET_KEY'])
    return 'Hello World!'


if __name__ == '__main__':
    app.run()