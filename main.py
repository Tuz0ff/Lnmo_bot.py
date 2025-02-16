import os
import psycopg2
from flask import Flask, render_template, request, redirect, url_for
import hashlib
import hmac
import json
from urllib.parse import parse_qs

app = Flask(__name__, template_folder='templates')

# Получение строки подключения из переменных окружения
DATABASE_URL = os.getenv('DATABASE_URL')

# Секретный ключ вашего бота (получите его у BotFather)
TELEGRAM_BOT_TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'

# Создание таблицы пользователей
def init_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            telegram_id INTEGER UNIQUE,
            login TEXT UNIQUE,
            password TEXT,
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

        # Проверяем наличие hash в данных
        if 'hash' not in data:
            return False

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
    return render_template('index.html')

# Обработка входа через Telegram
@app.route('/login_telegram', methods=['POST'])
def login_telegram():
    init_data = request.form['initData']
    if not verify_init_data(init_data):
        return "Ошибка авторизации."

    # Разбираем initData
    data = parse_qs(init_data)
    user_data = json.loads(data['user'][0])

    # Проверяем, есть ли пользователь в базе данных
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE telegram_id = %s', (user_data['id'],))
    user = cursor.fetchone()
    conn.close()

    if user:
        # Если пользователь найден, перенаправляем на страницу профиля
        return redirect(url_for('user_profile', user_id=user[0]))
    else:
        # Если пользователь не найден, предлагаем зарегистрироваться
        return redirect(url_for('register_telegram'))

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
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (telegram_id, login, quantity_of_coins) VALUES (%s, %s, %s)',
                       (user_data['id'], user_data.get('username', 'user'), 1))
        conn.commit()
        conn.close()
        return redirect(url_for('user_profile', user_id=user_data['id']))
    except psycopg2.IntegrityError:
        conn.close()
        return "Пользователь с таким Telegram ID уже существует."

# Страница профиля пользователя с количеством монет
@app.route('/profile/<int:user_id>')
def user_profile(user_id):
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return render_template('profile.html', login=user[2], coins=user[4])
    else:
        return "Пользователь не найден"

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
