#!/usr/bin/env python

from flask import Flask, jsonify, make_response, request
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from dotenv import load_dotenv

import uuid
import jwt
import datetime
import os

import hashlib

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
app.config['UPLOAD_FOLDER'] = './uploads/'

ALLOWED_FILE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'mkv', 'mp4', 'heic', 'pdf'}

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


class Types(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))


class Companies(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(255))
    name = db.Column(db.String(255))
    email = db.Column(db.String(255))
    password = db.Column(db.String(255))
    description = db.Column(db.Text)
    vat_number = db.Column(db.String(10))
    profile_picture = db.Column(db.String(255))
    type_id = db.Column(db.Integer, db.ForeignKey('types.id'), nullable=False)


class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    has_shift = db.Column(db.Boolean)


class Follows(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)


class Uploads(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    original_file_name = db.Column(db.String(255))
    hashed_file_name = db.Column(db.String(255))


def validate_file_extension(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_FILE_EXTENSIONS


def jwt_token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None

        token_header = 'X-Access-Token'

        if token_header in request.headers:
            token = request.headers[token_header]

        if not token:
            print("Token not valid")
            return jsonify({'message': 'Valid Auth token is required!'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
            if not current_user:
                current_user = Companies.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Invalid Auth token!'})

        return f(current_user, *args, **kwargs)

    return decorator


@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    check = Users.query.filter_by(email=data['email']).all()
    if (check):
        return jsonify({'message': f'User {data["email"]} already exist!'})
    user = Users(public_id=str(uuid.uuid4()), username=data['username'], password=hashed_password, email=data['email'])

    db.session.add(user)
    db.session.commit()

    return jsonify({'message': f'User {data["username"]} created successfully!'})


@app.route('/login', methods=['POST'])
def login_user():
    auth = request.authorization
    print(auth)
    if not auth or not auth.username or not auth.password:
        return make_response('User could not be verified!', 401, {'Authentication': 'Login required'})
    user_type = "user"
    user = Users.query.filter_by(email=auth.username).first()

    if not user:
        user = Companies.query.filter_by(email=auth.username).first()
        user_type = "company"

    print(auth.password)
    print(user.password)

    result = check_password_hash(user.password, auth.password)
    print(result)

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=45)},
            app.config['SECRET_KEY'], "HS256")

        return jsonify({'token': token, 'user_type': user_type})

    return make_response('User could not be verified!', 401, {'Authentication': 'Login required'})


@app.route('/create_company', methods=['POST'])
def create_company():
    data = request.get_json()
    check = Companies.query.filter_by(email=data['email']).all()
    if (check):
        return jsonify({'message': f'Company {data["email"]} already exist!'})
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_company = Companies(name=data['email'], public_id=str(uuid.uuid4()), email=data['email'],
                            vat_number=data['vat_number'],
                            password=hashed_password, type_id=data['type_id'])

    db.session.add(new_company)
    db.session.commit()
    return jsonify({'message': f'new company ({data["name"]}) created'})


@app.route('/companies/filter-by/type/<type_id>', methods=['GET'])
@jwt_token_required
def filter_companies(current_user, type_id):
    companies = Companies.query.filter_by(type_id=type_id).all()

    response = []

    for company in companies:
        c_type = Types.query.filter_by(id=type_id).first()
        o = {
            "company_name": company.name,
            "type": c_type.name
        }
        response.append(o)
        print(company.name)

    return jsonify({'list_of_companies': response})


@app.route('/delete_company/<company_id>', methods=['DELETE'])
@jwt_token_required
def delete_company(current_user, company_id):
    data = request.get_json()
    company = Companies.query.filter_by(id=data['company_id'], user_id=current_user.id.first())
    if not company:
        return jsonify({'message': 'company does no exist'})

    db.session.delete(company)
    db.session.commit()
    return jsonify({'message': 'Company deleted'})


@app.route('/create_employee', methods=['POST'])
@jwt_token_required
def create_employee(current_user):
    if type(current_user) is Companies:
        data = request.get_json()
        print(data)
        new_employee = Employee(employee_id=data['user_id'], company_id=current_user.id)

        db.session.add(new_employee)
        db.session.commit()

        return jsonify({'message': 'new employee created'})

    return make_response(f'Only company can delete employee!', 403)


@app.route('/delete_employee/<employee_id>', methods=['DELETE'])
@jwt_token_required
def delete_employee(current_user, employee_id):
    data = request.get_json()
    new_employee = Employee(name=data['name'], description=data['description'], vat_number=data['vat_number'],
                            profile_picture=data['profile_picture'], employee_id=data['user_id'])
    db.session.add(new_employee)
    db.session.commit()
    # return jsonify({'message': 'new company created'})

    print(type(current_user))

    # only company can delete employee
    if type(current_user) is Companies:
        print(f'Logged company {current_user.name}')
        employee = Employee.query.filter_by(id=employee_id).first()

        if not employee:
            return make_response(f'Employee id {employee_id} was not found!', 503)

        db.session.delete(employee)
        db.session.commit()

        return jsonify({'message': f'Employee "{employee.id}" deleted!'})

    return make_response(f'Only company can delete employee!', 403)


@app.route("/upload", methods=['POST'])
@jwt_token_required
def upload(current_user):
    print(request.files)
    if 'file' in request.files:
        file = request.files['file']
        if file and validate_file_extension(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            return make_response(f'File {file.filename} uploaded successfully!', 200)
    return make_response('Failed to upload file', 503)


@app.route("/v1/api/user", methods=["GET"])
@jwt_token_required
def get_user_data(current_user):
    print(current_user)
    user = None

    response = {}

    if type(current_user) is Companies:
        print(f'Logged company {current_user.name}')
        user = Companies.query.filter_by(id=current_user.id).first()

        company_type = Types.query.filter_by(id=user.type_id).first().name

        response = {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "is_company": True,
            "type": company_type
        }

    elif type(current_user) is Users:
        print(f'Logged user: {current_user.email}')
        user = Users.query.filter_by(id=current_user.id).first()
        response = {
            "id": user.id,
            "name": user.username,
            "email": user.email,
            "is_company": False
        }
    return jsonify(response)


@app.route("/change", methods=["PUT"])
@jwt_token_required
def change_name(current_user):
    data = request.get_json()
    response = {}
    for i in data:
        setattr(current_user, i, data[i])
        print(i)
    db.session.commit()
    response = {'message': "User name has been changed"}
    db.session.commit()
    return jsonify(response)


@app.route('/')
def hello_world():
    print(app.config['SQLALCHEMY_DATABASE_URI'])
    print(app.config['SECRET_KEY'])
    return 'Hello World!'


if __name__ == '__main__':
    app.run()
