import os
from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
import bcrypt
from datetime import timedelta

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'supersecretkey')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)

jwt = JWTManager(app)

# Usuarios en memoria (solo para pruebas/demos, se borra al reiniciar)
users = {}
user_id_counter = 1

@app.route('/register', methods=['POST'])
def register():
    global user_id_counter
    data = request.get_json()
    username = data['username']
    password = data['password']
    if username in users:
        return jsonify(msg='Usuario ya existe'), 409
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = {
        'id': user_id_counter,
        'username': username,
        'password': hashed.decode('utf-8')
    }
    user_id_counter += 1
    return jsonify(msg='Usuario registrado'), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user = users.get(username)
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        access_token = create_access_token(identity=str(user['id']))
        refresh_token = create_refresh_token(identity=str(user['id']))
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200
    return jsonify(msg='Credenciales incorrectas'), 401

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=str(user_id))
    return jsonify(access_token=new_access_token), 200

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    return jsonify(msg=f'Acceso concedido al usuario {user_id}')

@app.route('/')
def home():
    return jsonify(msg='API Flask sin base de datos funcionando en Vercel')

# Handler para Vercel
# https://vercel.com/docs/functions/serverless-functions/runtimes/python
# Vercel busca la función llamada 'app' o 'handler'
def handler(environ, start_response):
    return app(environ, start_response)
