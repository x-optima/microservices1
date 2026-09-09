# Сервис аутентификации (security).
# Регистрация, вход и проверка JWT. Шлюз NGINX использует его через auth_request:
# GET /v1/token/validation возвращает 2xx для валидного токена и 401 для
# любого другого — остальные коды шлюз превратит в 500.

from os import getenv
from flask import Flask, request, make_response, jsonify
from prometheus_flask_exporter import PrometheusMetrics, NO_PREFIX
from passlib.hash import pbkdf2_sha256
import jwt

server = Flask(__name__)
# Инициализация экспорта метрик Prometheus.
# Эндпоинт /metrics доступен для мониторинга (Grafana, Prometheus).
metrics = PrometheusMetrics(server, defaults_prefix=NO_PREFIX, buckets=[0.1, 0.5, 1, 1.5, 2], default_labels={"app_name": "security"})
metrics.info('app_info', 'Application info', version='1.0')

# Секретный ключ для подписи JWT-токенов (алгоритм HS256).
# В производственной среде значение должно храниться в переменной окружения.
jwt_key = 'secret'

# Хранилище пользователей в оперативной памяти.
# Формат: {логин: хеш_пароля}.
# В производственной среде вместо словаря используется база данных.
# Пароли хранятся только в виде хешей (pbkdf2_sha256 с солью).
# Восстановить исходный пароль из хеша невозможно.
data = {
    'bob': pbkdf2_sha256.hash('qwe123')
}

@server.route('/status', methods=['GET'])
def status():
    # Health-эндпоинт для проверки работоспособности сервиса.
    return {'status':'OK'}

def extract_token_payload():
    # Разбор заголовка Authorization: Bearer <jwt> и проверка подписи.
    # Возвращает (данные_токена, None) при успехе или (None, ответ_401) при ошибке.
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return None, (make_response(jsonify({'error':'Missing Authorization header'})), 401)

    try:
        auth_header_parts = auth_header.split(' ')
        auth_schema = auth_header_parts[0]
        auth_token = auth_header_parts[1]
    except IndexError:
        # Схема указана без значения, например только "Bearer".
        return None, (make_response(jsonify({'error':'Invalid Authorization header'})), 401)

    if not auth_schema == 'Bearer':
        return None, (make_response(jsonify({'error':'Invalid Authorization schema'})), 401)

    if not auth_token:
        return None, (make_response(jsonify({'error':'Invalid Authorization value'})), 401)

    try:
        # Проверка подписи и стандартных полей (exp, iat, nbf).
        # Алгоритм задаётся явно — защита от подмены алгоритма.
        return jwt.decode(auth_token, jwt_key, algorithms="HS256"), None
    except jwt.ExpiredSignatureError:
        return None, (make_response(jsonify({'error':'Signature expired. Please log in again.'})), 401)
    except jwt.InvalidTokenError:
        # Важно вернуть именно код 401, а не 200 с текстом ошибки — иначе
        # auth_request сочтёт некорректный токен успешной аутентификацией.
        return None, (make_response(jsonify({'error':'Invalid token. Please log in again.'})), 401)

@server.route('/v1/user', methods=['POST'])
def register():
    # Регистрация: создаём пользователя из пары login/password.
    # Шлюз направляет сюда POST /v1/register.
    if not request.json or not 'login' in request.json or not 'password' in request.json:
        return make_response(jsonify({'error':'Bad request'})), 400

    login = request.json['login']
    password = request.json['password']

    if login in data:
        # 409 Conflict: логин занят, повторная регистрация не проходит.
        return make_response(jsonify({'error':'User already exists'})), 409

    data[login] = pbkdf2_sha256.hash(password)
    return make_response(jsonify({'login': login})), 201

@server.route('/v1/user', methods=['GET'])
def user_info():
    # Логин текущего пользователя берём из данных токена.
    # Токен проверяем сами, не полагаясь только на шлюз.
    payload, error = extract_token_payload()
    if error:
        return error

    return {'login': payload['sub']}

@server.route('/v1/token', methods=['POST'])
def login():
    # Логин: сверяем пароль с хешем и создаём JWT с sub = login.
    if not request.json or not 'login' in request.json or not 'password' in request.json:
        return make_response(jsonify({'error':'Bad request'})), 400

    login = request.json['login']
    password = request.json['password']

    if not login in data:
        # Единое сообщение для неизвестного логина и неверного пароля:
        # не раскрываем злоумышленнику, какие логины существуют.
        return make_response(jsonify({'error':'Unknown login or password'})), 401

    hash = data[login]
    if not pbkdf2_sha256.verify(password, hash):
        return make_response(jsonify({'error':'Unknown login or password'})), 401

    return jwt.encode({'sub': login}, jwt_key, algorithm="HS256")

@server.route('/v1/token/validation', methods=['GET'])
def validate():
    # Проверка токена для шлюза (auth_request): корректный токен — код 2xx,
    # некорректный — код 401.
    payload, error = extract_token_payload()
    if error:
        return error

    return payload

if __name__ == '__main__':
    # Порт берём из env (compose передаёт 3000), по умолчанию 8080.
    port = int(getenv('PORT') or '8080')
    server.run(host='0.0.0.0', port=port)
