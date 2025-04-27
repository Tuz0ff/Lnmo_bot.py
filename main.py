from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, send_file
import sqlite3
import hashlib
import jwt
from functools import wraps
import pandas as pd
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
from io import BytesIO

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'ivanZoloTop148832252'


def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS coins_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            date DATE,
            coins INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('index'))

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (data['user_id'],))
            current_user = cursor.fetchone()
            conn.close()

            if not current_user:
                return redirect(url_for('index'))
        except:
            return redirect(url_for('index'))

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/check_auth')
def check_auth():
    token = request.cookies.get('token')
    if not token:
        return jsonify({'authenticated': False}), 401

    try:
        jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'authenticated': True}), 200
    except:
        return jsonify({'authenticated': False}), 401


@app.route('/')
def index():
    token = request.cookies.get('token')
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            return redirect(url_for('user_profile', user_id=data['user_id']))
        except:
            pass
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    login = request.form['login']
    password = request.form['password']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE login = ? AND password = ?', (login, hashed_password))
    user = cursor.fetchone()
    conn.close()

    if user:
        token = jwt.encode({
            'user_id': user[0],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'])

        response = make_response(redirect(url_for('user_profile', user_id=user[0])))
        response.set_cookie('token', token, httponly=True, secure=True, samesite='Strict')
        return response
    else:
        return "Неверный логин или пароль", 401


@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('index')))
    response.set_cookie('token', '', expires=0)
    return response


@app.route('/profile/<int:user_id>')
@token_required
def user_profile(current_user, user_id):
    if current_user[0] != user_id:
        return redirect(url_for('user_profile', user_id=current_user[0]))

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        coins = user[3] if user[3] is not None else 0
        is_admin = user[4] if user[4] is not None else False
        is_superadmin = user[1] == "superadmin"
        message = request.args.get('message')

        return render_template('profile.html',
                               login=user[1],
                               coins=coins,
                               is_admin=is_admin,
                               is_superadmin=is_superadmin,
                               user_id=user_id,
                               message=message,
                               user=user)
    else:
        return redirect(url_for('index'))


@app.route('/coins_chart/<int:user_id>')
@token_required
def coins_chart(current_user, user_id):
    if current_user[0] != user_id:
        return redirect(url_for('index'))

    conn = sqlite3.connect('users.db')
    df = pd.read_sql('''
        SELECT date, coins 
        FROM coins_history 
        WHERE user_id = ? 
        ORDER BY date ASC
    ''', conn, params=(user_id,))
    conn.close()

    plt.style.use('dark_background')
    plt.figure(figsize=(2, 1))
    plt.plot(df['date'], df['coins'], marker='o', linestyle='-', color='#4361ee', markersize=3)
    plt.title('')
    plt.xlabel('')
    plt.ylabel('')
    plt.grid(True, color='#2a3a5a', linestyle='--', linewidth=0.5)
    plt.gca().set_facecolor('none')
    plt.gcf().set_facecolor('none')
    plt.xticks([])
    plt.yticks([])
    plt.tight_layout(pad=0)

    buffer = BytesIO()
    plt.savefig(buffer, format='png', bbox_inches='tight', transparent=True)
    buffer.seek(0)
    plt.close()

    return send_file(buffer, mimetype='image/png')


@app.route('/make_admin', methods=['POST'])
@token_required
def make_admin(current_user):
    try:
        if current_user[1] != "superadmin":
            return redirect(url_for('user_profile', user_id=current_user[0], message="У вас нет прав"))

        user_login = request.form.get('user_login')
        if not user_login:
            return redirect(url_for('user_profile', user_id=current_user[0], message="Логин пользователя не указан"))

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE login = ?', (user_login,))
        user = cursor.fetchone()

        if not user:
            conn.close()
            return redirect(url_for('user_profile', user_id=current_user[0], message="Пользователь не найден"))

        cursor.execute('UPDATE users SET is_admin = TRUE WHERE id = ?', (user[0],))
        conn.commit()
        conn.close()

        return redirect(url_for('user_profile',
                                user_id=current_user[0],
                                message=f"Пользователь {user_login} назначен администратором"))

    except Exception as e:
        print(f"Ошибка: {str(e)}")
        return redirect(url_for('user_profile',
                                user_id=current_user[0],
                                message="Ошибка сервера"))


@app.route('/register_page')
def register_page():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register():
    login = request.form['login']
    password = request.form['password']
    role = request.form['role']
    user_class = request.form.get('class') if role == 'student' else None
    direction = request.form.get('direction') if role == 'student' else None

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if login == 'superadmin':
        is_admin = True
        role = 'teacher'
    else:
        is_admin = False

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO users (login, password, quantity_of_coins, is_admin, class, direction, role)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (login, hashed_password, 0, is_admin, user_class, direction, role))
        conn.commit()
        conn.close()
        return render_template('registration_success.html')
    except sqlite3.IntegrityError:
        conn.close()
        return "Пользователь с таким логином уже существует.", 400


@app.route('/get_users_by_class')
@token_required
def get_users_by_class(current_user):
    if not current_user[4]:
        return jsonify({'error': 'Unauthorized'}), 403

    class_name = request.args.get('class')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, login, quantity_of_coins FROM users WHERE class = ? AND role = "student"', (class_name,))
    users = cursor.fetchall()
    conn.close()

    user_list = [{'id': user[0], 'login': user[1], 'quantity_of_coins': user[2]} for user in users]
    return jsonify({'users': user_list})


@app.route('/get_users_by_class_and_direction')
@token_required
def get_users_by_class_and_direction(current_user):
    if not current_user[4]:
        return jsonify({'error': 'Unauthorized'}), 403

    class_name = request.args.get('class')
    direction = request.args.get('direction')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, login, quantity_of_coins FROM users WHERE class = ? AND direction = ? AND role = "student"',
        (class_name, direction))
    users = cursor.fetchall()
    conn.close()

    user_list = [{'id': user[0], 'login': user[1], 'quantity_of_coins': user[2]} for user in users]
    return jsonify({'users': user_list})


@app.route('/update_coins', methods=['POST'])
@token_required
def update_coins(current_user):
    if not current_user[4]:
        return jsonify({'error': 'Unauthorized'}), 403

    user_ids = request.form.getlist('user_ids')
    add_coins = int(request.form['add_coins'])

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    for user_id in user_ids:
        cursor.execute('''
            INSERT INTO coins_history (user_id, date, coins)
            VALUES (?, ?, ?)
        ''', (user_id, datetime.now().date(), add_coins))

        cursor.execute('SELECT quantity_of_coins FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            new_coins = user[0] + add_coins
            cursor.execute('UPDATE users SET quantity_of_coins = ? WHERE id = ?', (new_coins, user_id))

    conn.commit()
    conn.close()
    return redirect(url_for('user_profile', user_id=current_user[0], message="Монеты успешно добавлены"))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
