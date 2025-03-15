from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import hashlib

app = Flask(__name__, template_folder='templates')

# Создание базы данных и таблицы пользователей
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Создание таблицы, если она не существует
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE,
            password TEXT,
            quantity_of_coins INTEGER DEFAULT 0,
            is_admin BOOLEAN DEFAULT FALSE,
            class TEXT,
            direction TEXT,
            role TEXT DEFAULT 'student'
        )
    ''')

    # Проверка наличия столбцов и их добавление, если они отсутствуют
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]

    if 'class' not in columns:
        cursor.execute('ALTER TABLE users ADD COLUMN class TEXT')

    if 'direction' not in columns:
        cursor.execute('ALTER TABLE users ADD COLUMN direction TEXT')

    if 'role' not in columns:
        cursor.execute('ALTER TABLE users ADD COLUMN role TEXT DEFAULT "student"')

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
        message = request.args.get('message')  # Получаем сообщение из параметров запроса
        return render_template('profile.html', login=user[1], coins=coins, is_admin=is_admin, is_superadmin=is_superadmin, user_id=user_id, message=message, user=user)
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
    role = request.form['role']
    user_class = request.form.get('class') if role == 'student' else None
    direction = request.form.get('direction') if role == 'student' else None

    # Хэширование пароля
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Добавление пользователя в базу данных
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO users (login, password, quantity_of_coins, is_admin, class, direction, role)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (login, hashed_password, 0, False, user_class, direction, role))
        conn.commit()
        conn.close()
        return render_template('registration_success.html')
    except sqlite3.IntegrityError:
        conn.close()
        return "Пользователь с таким логином уже существует."


@app.route('/get_users_by_class')
def get_users_by_class():
    class_name = request.args.get('class')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, login, quantity_of_coins FROM users WHERE class = ? AND role = "student"', (class_name,))
    users = cursor.fetchall()
    conn.close()

    # Преобразуем данные в JSON
    user_list = [{'id': user[0], 'login': user[1], 'quantity_of_coins': user[2]} for user in users]
    return {'users': user_list}

@app.route('/get_users_by_class_and_direction')
def get_users_by_class_and_direction():
    class_name = request.args.get('class')
    direction = request.args.get('direction')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, login, quantity_of_coins FROM users WHERE class = ? AND direction = ? AND role = "student"', (class_name, direction))
    users = cursor.fetchall()
    conn.close()

    # Преобразуем данные в JSON
    user_list = [{'id': user[0], 'login': user[1], 'quantity_of_coins': user[2]} for user in users]
    return {'users': user_list}

@app.route('/update_coins', methods=['POST'])
def update_coins():
    admin_id = request.form.get('admin_id')  # ID администратора
    user_ids = request.form.getlist('user_ids')  # Список ID выделенных пользователей
    add_coins = int(request.form['add_coins'])  # Количество монет для прибавления

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Проверяем, что admin_id принадлежит администратору
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (admin_id,))
    admin = cursor.fetchone()

    if admin and admin[0]:  # Проверка, что это администратор
        for user_id in user_ids:
            # Находим пользователя по ID
            cursor.execute('SELECT quantity_of_coins FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()

            if user:
                current_coins = user[0]
                new_coins = current_coins + add_coins  # Прибавляем монеты
                # Обновляем количество монет у пользователя
                cursor.execute('UPDATE users SET quantity_of_coins = ? WHERE id = ?', (new_coins, user_id))

        conn.commit()
        conn.close()
        return redirect(url_for('user_profile', user_id=admin_id, message=f"Монеты успешно прибавлены выделенным пользователям"))
    else:
        conn.close()
        return redirect(url_for('user_profile', user_id=admin_id, message="У вас нет прав для выполнения этого действия."))

@app.route('/subtract_coins', methods=['POST'])
def subtract_coins():
    admin_id = request.form.get('admin_id')  # ID администратора
    user_ids = request.form.getlist('user_ids')  # Список ID выделенных пользователей
    subtract_coins = int(request.form['subtract_coins'])  # Количество монет для убавления

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Проверяем, что admin_id принадлежит администратору
    cursor.execute('SELECT is_admin FROM users WHERE id = ?', (admin_id,))
    admin = cursor.fetchone()

    if admin and admin[0]:  # Проверка, что это администратор
        for user_id in user_ids:
            # Находим пользователя по ID
            cursor.execute('SELECT quantity_of_coins FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()

            if user:
                current_coins = user[0]
                new_coins = current_coins - subtract_coins  # Убавляем монеты
                if new_coins < 0:
                    new_coins = 0  # Не допускаем отрицательного количества монет
                # Обновляем количество монет у пользователя
                cursor.execute('UPDATE users SET quantity_of_coins = ? WHERE id = ?', (new_coins, user_id))

        conn.commit()
        conn.close()
        return redirect(url_for('user_profile', user_id=admin_id, message=f"Монеты успешно убавлены выделенным пользователям"))
    else:
        conn.close()
        return redirect(url_for('user_profile', user_id=admin_id, message="У вас нет прав для выполнения этого действия."))

@app.route('/make_admin', methods=['POST'])
def make_admin():
    superadmin_id = request.form.get('superadmin_id')  # ID суперадмина
    user_login = request.form['user_login']  # Логин пользователя, которого нужно назначить администратором

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Проверяем, что superadmin_id принадлежит superadmin
    cursor.execute('SELECT login FROM users WHERE id = ?', (superadmin_id,))
    superadmin = cursor.fetchone()

    if superadmin and superadmin[0] == 1:  # Проверка, что это superadmin
        # Находим пользователя по логину
        cursor.execute('SELECT id FROM users WHERE login = ?', (user_login,))
        user = cursor.fetchone()

        if user:
            user_id = user[0]
            # Назначаем пользователя администратором
            cursor.execute('UPDATE users SET is_admin = TRUE WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            return redirect(url_for('user_profile', user_id=superadmin_id, message=f"Пользователь {user_login} успешно назначен администратором"))
        else:
            conn.close()
            return redirect(url_for('user_profile', user_id=superadmin_id, message="Пользователь с таким логином не найден."))
    else:
        conn.close()
        return redirect(url_for('user_profile', user_id=superadmin_id, message="У вас не хватает прав"))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
