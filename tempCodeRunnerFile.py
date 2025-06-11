from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
from flask_cors import CORS
import bcrypt
import MySQLdb.cursors
import secrets
from datetime import timedelta

app = Flask(__name__)
CORS(app)

# Configuración de MySQL y JWT
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '123456789'
app.config['MYSQL_DB'] = 'auth_demo'
app.config['MYSQL_PORT'] = 3307
app.config['JWT_SECRET_KEY'] = secrets.token_urlsafe(32)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)

mysql = MySQL(app)
jwt = JWTManager(app)

# Registro de usuario
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cursor = mysql.connection.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed.decode('utf-8')))
        mysql.connection.commit()
        return jsonify(msg='Usuario registrado'), 201
    except Exception:
        return jsonify(msg='Usuario ya existe'), 409

# Login y generación de tokens
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        access_token = create_access_token(identity=str(user['id']))
        refresh_token = create_refresh_token(identity=str(user['id']))
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200
    return jsonify(msg='Credenciales incorrectas'), 401

# Renovación de token
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=str(user_id))
    return jsonify(access_token=new_access_token), 200

# Ruta protegida
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    return jsonify(msg=f'Acceso concedido al usuario {user_id}')

if __name__ == '__main__':
    app.run(debug=True)
