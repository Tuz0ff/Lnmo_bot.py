from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
import hashlib
import hmac
import json
from urllib.parse import parse_qs
from flask_cors import CORS

app = Flask(__name__, template_folder='templates')
CORS(app)

# Секретный ключ вашего бота (получите его у BotFather)
TELEGRAM_BOT_TOKEN = '7789697745:AAHgg_-f4tjpswEKgnbQujUSkKuWp8TIsnw'

# Создание базы данных и таблицы пользователей
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id INTEGER UNIQUE,
            login TEXT UNIQUE,
            password TEXT,
            year_of_born INTEGER,
            quantity_of_coins INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()
    print("База данных инициализирована")  # Отладочный вывод

# Проверка подлинности initData от Telegram
def verify_init_data(init_data):
    try:
        print("Полученный initData:", init_data)  # Отладочный вывод
        data = parse_qs(init_data)
        hash_str = data['hash'][0]
        print("Hash из initData:", hash_str)  # Отладочный вывод

        data_check_string = '\n'.join(f"{k}={v[0]}" for k, v in sorted(data.items()) if k != 'hash')
        print("Строка для проверки:", data_check_string)  # Отладочный вывод

        secret_key = hmac.new(b"WebAppData", TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
        computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        print("Вычисленный hash:", computed_hash)  # Отладочный вывод

        return computed_hash == hash_str
    except Exception as e:
        print(f"Ошибка проверки initData: {e}")
        return False

# Главная страница с формой авторизации
@app.route('/')
def index():
    return render_template('index.html')

# Авторизация через логин и пароль
@app.route('/login', methods=['POST'])
def login():
    login = request.form['login']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE login = ? AND password = ?', (login, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        # Если пользователь найден, перенаправляем на страницу приветствия
        return "Добро пожаловать!"
    else:
        # Если пользователь не найден, возвращаем ошибку
        return "Неверный логин или пароль."

# Авторизация через Telegram
@app.route('/login_telegram', methods=['POST'])
def login_telegram():
    init_data = request.form['initData']
    print("Полученный initData в /login_telegram:", init_data)  # Отладочный вывод

    if not verify_init_data(init_data):
        return "Ошибка авторизации."

    data = parse_qs(init_data)
    user_data = json.loads(data['user'][0])
    print("Данные пользователя:", user_data)  # Отладочный вывод

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE telegram_id = ?', (user_data['id'],))
    user = cursor.fetchone()
    conn.close()

    if user:
        # Если пользователь найден, перенаправляем на страницу приветствия
        return "Добро пожаловать!"
    else:
        # Если пользователь не найден, предлагаем зарегистрироваться
        return "Пользователь не найден. Пожалуйста, зарегистрируйтесь."

# Страница приветствия
@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

# Регистрация нового пользователя
@app.route('/register', methods=['POST'])
def register():
    login = request.form['login']
    password = request.form['password']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (login, password) VALUES (?, ?)', (login, password))
        conn.commit()
        conn.close()
        return "Регистрация успешна!"
    except sqlite3.IntegrityError:
        conn.close()
        return "Пользователь с таким логином уже существует."

# Страница регистрации
@app.route('/register_page')
def register_page():
    return render_template('register.html')

# Регистрация нового пользователя через Telegram
@app.route('/register_telegram', methods=['POST'])
def register_telegram():
    init_data = request.form['initData']
    print("Полученный initData в /register_telegram:", init_data)  # Отладочный вывод

    if not verify_init_data(init_data):
        return "Ошибка авторизации."

    data = parse_qs(init_data)
    user_data = json.loads(data['user'][0])
    print("Данные пользователя:", user_data)  # Отладочный вывод

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (telegram_id, login, quantity_of_coins) VALUES (?, ?, ?)',
                       (user_data['id'], user_data.get('username', 'user'), 0))
        conn.commit()
        conn.close()
        return "Регистрация успешна!"
    except sqlite3.IntegrityError:
        conn.close()
        return "Пользователь с таким Telegram ID уже существует."

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=10000, debug=True)
