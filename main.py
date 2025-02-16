import os
import psycopg2
from flask import Flask, render_template, request, redirect, url_for
import hashlib

app = Flask(__name__, template_folder='templates')

# Получение строки подключения из переменных окружения
DATABASE_URL = os.getenv('postgresql://lnmobot_database_nkjw_user:hB6Bs5tb7c6H5DjNTBnBEnyilQhCZrYj@dpg-cup55daj1k6c739g1c1g-a/lnmobot_database_nkjw')

# Создание таблицы пользователей
def init_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            login TEXT UNIQUE,
            password TEXT,
            quantity_of_coins INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

# Главная страница с формой авторизации
@app.route('/')
def index():
    return render_template('index.html')

# Обработка входа по логину и паролю
@app.route('/login', methods=['POST'])
def login():
    login = request.form['login']
    password = request.form['password']

    # Хэшируем пароль для сравнения с базой данных
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Проверяем, есть ли пользователь в базе данных
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE login = %s AND password = %s', (login, hashed_password))
    user = cursor.fetchone()
    conn.close()

    if user:
        # Если пользователь найден, перенаправляем на страницу с количеством монет
        return redirect(url_for('user_profile', user_id=user[0]))
    else:
        # Если пользователь не найден, возвращаем ошибку
        return "Неверный логин или пароль"

# Страница профиля пользователя с количеством монет
@app.route('/profile/<int:user_id>')
def user_profile(user_id):
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return render_template('profile.html', login=user[1], coins=user[3])
    else:
        return "Пользователь не найден"

# Страница регистрации
@app.route('/register_page')
def register_page():
    return render_template('register.html')

# Обработка регистрации
@app.route('/register', methods=['POST'])
def register():
    login = request.form['login']
    password = request.form['password']

    # Хэшируем пароль
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Добавляем пользователя в базу данных
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (login, password, quantity_of_coins) VALUES (%s, %s, %s)',
                       (login, hashed_password, 1))
        conn.commit()
        conn.close()
        return render_template('registration_success.html')
    except psycopg2.IntegrityError:
        conn.close()
        return "Пользователь с таким логином уже существует."

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
