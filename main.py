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
            quantity_of_coins INTEGER DEFAULT 0,
            is_admin BOOLEAN DEFAULT FALSE
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
        coins = user[3] if user[3] is not None else 0
        is_admin = user[4] if user[4] is not None else False
        is_superadmin = user[1] == "superadmin"  # Проверка, является ли пользователь superadmin
        return render_template('profile.html', login=user[1], coins=coins, is_admin=is_admin, is_superadmin=is_superadmin, user_id=user_id)
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
        cursor.execute('INSERT INTO users (login, password, quantity_of_coins, is_admin) VALUES (?, ?, ?, ?)',
                       (login, hashed_password, 0, False))
        conn.commit()
        conn.close()
        return render_template('registration_success.html')
    except sqlite3.IntegrityError:
        conn.close()
        return "Пользователь с таким логином уже существует."

# Обновление количества монет
@app.route('/update_coins', methods=['POST'])
def update_coins():
    admin_id = request.form.get('admin_id')  # ID администратора
    user_id = request.form['user_id']  # ID пользователя, у которого нужно изменить монеты
    new_coins = request.form['new_coins']  # Новое количество монет

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Проверяем, что admin_id принадлежит администратору
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (1,))
    admin = cursor.fetchone()

    if admin and admin[0]:  # Проверка, что это администратор
        # Обновляем количество монет у пользователя
        cursor.execute('UPDATE users SET quantity_of_coins = ? WHERE id = ?', (new_coins, user_id))
        conn.commit()
        conn.close()
        return redirect(url_for('user_profile', user_id=user_id))
    else:
        conn.close()
        return "У вас нет прав для выполнения этого действия."

# Назначение администратора
@app.route('/make_admin', methods=['POST'])
def make_admin():
    superadmin_id = request.form.get('superadmin_id')  # ID суперадмина
    user_id = request.form['user_id']  # ID пользователя, которого нужно назначить администратором

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Проверяем, что superadmin_id принадлежит пользователю с логином "superadmin"
    cursor.execute('SELECT login FROM users WHERE id = ?', (1,))
    superadmin = cursor.fetchone()

    if superadmin and superadmin[0] == "superadmin":  # Проверка, что это superadmin
        # Назначаем пользователя администратором
        cursor.execute('UPDATE users SET is_admin = TRUE WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        return redirect(url_for('user_profile', user_id=user_id))
    else:
        conn.close()
        return "У вас нет прав для выполнения этого действия."

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
