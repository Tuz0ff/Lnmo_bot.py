from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
import hashlib
import hmac
import json
from urllib.parse import parse_qs

app = Flask(__name__, template_folder='templates')

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

# Проверка подлинности initData от Telegram
def verify_init_data(init_data):
    try:
        # Разбираем initData
        data = parse_qs(init_data)
        hash_str = data['hash'][0]

        # Сортируем данные и создаем строку для проверки
        data_check_string = '\n'.join(f"{k}={v[0]}" for k, v in sorted(data.items()) if k != 'hash')

        # Создаем секретный ключ
        secret_key = hmac.new(b"WebAppData", TELEGRAM_BOT_TOKEN.encode(), hashlib.sha256).digest()
        computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

        # Сравниваем хэши
        return computed_hash == hash_str
    except Exception as e:
        print(f"Ошибка проверки initData: {e}")
        return False

# Главная страница с формой авторизации
@app.route('/')
def index():
    # Получаем initData из запроса
    init_data = request.args.get('initData')
    if init_data and verify_init_data(init_data):
        # Разбираем initData
        data = parse_qs(init_data)
        user_data = json.loads(data['user'][0])

        # Проверяем, есть ли пользователь в базе данных
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE telegram_id = ?', (user_data['id'],))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Если пользователь найден, перенаправляем на страницу приветствия
            return render_template('welcome.html', login=user[2], coins=user[5])
        else:
            # Если пользователь не найден, предлагаем зарегистрироваться
            return redirect(url_for('register_page'))
    else:
        return render_template('index.html')

# Страница регистрации
@app.route('/register_page')
def register_page():
    return render_template('register.html')

# Регистрация нового пользователя через Telegram
@app.route('/register_telegram', methods=['POST'])
def register_telegram():
    init_data = request.form['initData']
    if not verify_init_data(init_data):
        return "Ошибка авторизации."

    # Разбираем initData
    data = parse_qs(init_data)
    user_data = json.loads(data['user'][0])

    # Добавляем пользователя в базу данных
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
    app.run(debug=True)