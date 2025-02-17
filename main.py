from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import hashlib

app = Flask(__name__, template_folder='templates')

# Создание базы данных и таблицы пользователей
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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

    # Хэширование пароля
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Проверка, есть ли пользователь в базе данных
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE login = ? AND password = ?', (login, hashed_password))
    user = cursor.fetchone()
    conn.close()

    if user:
        # Если пользователь найден, перенаправляем на страницу с количеством монет
        return redirect(url_for('user_profile', user_id=user[0]))
    else:
        # Если пользователь не найден, возвращаем ошибку
        return "Неверный логин или пароль"

# Страница профиля с количеством монет
@app.route('/profile/<int:user_id>')
def user_profile(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        # Убедимся, что coins не None
        coins = user[4] if user[4] is not None else 0
        return render_template('profile.html', login=user[1], coins=coins)
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

    # Хэширование пароля
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Добавление пользователя в базу данных
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (login, password, quantity_of_coins) VALUES (?, ?, ?)',
                       (login, hashed_password, 0))
        conn.commit()
        conn.close()
        return render_template('registration_success.html')
    except sqlite3.IntegrityError:
        conn.close()
        return "Пользователь с таким логином уже существует."

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
