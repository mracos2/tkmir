from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3  # Импортируем sqlite3
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Замени на свой секретный ключ!  Очень важно!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Создадим базу данных для пользователей
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Функция, которая будет обрабатывать вход

# -------------------- Модели данных --------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=db.func.now()) # Исправлено
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Связь с User
    author = db.relationship('User', backref=db.backref('news', lazy=True)) # Обратная связь
    slug = db.Column(db.String(255), unique=True, nullable=False) # URL-friendly заголовок
    is_published = db.Column(db.Boolean, default=False) # Статус публикации

    def __repr__(self):
        return f'<News {self.title}>'

# -------------------- Функции Flask-Login --------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- Маршруты (Routes) для авторизации --------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('admin_panel'))  # Перенаправляем на админ панель
        else:
            flash('Неверное имя пользователя или пароль', 'danger')
    return render_template('login.html')  # Создай файл login.html

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))  # Перенаправляем на главную

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Проверка, существует ли пользователь с таким именем
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Имя пользователя уже занято.', 'danger')
            return render_template('register.html') # Создай файл register.html

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Вы успешно зарегистрировались! Теперь войдите.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html') # Создай файл register.html

@app.route('/protected')
@login_required
def protected():
    return f'<h1>Привет, {current_user.username}! Это защищенная страница.</h1> <a href="{url_for("logout")}">Выйти</a>'  # Замени на свою защищенную страницу

# -------------------- Маршруты (Routes) для существующего функционала --------------------

EMAIL_REGEX = r'^[\w\.-]+@[\w\.-]+\.\w+$'

@app.route('/subscribe', methods=['POST'])
def subscribe():
    from db.emails_create import create_connection as create_email_connection, add_email  # Импорт внутри функции
    conn = create_email_connection()
    if not conn:
        return jsonify({"error": "Database error"}), 500

    email = request.form.get('email')

    if not re.match(EMAIL_REGEX, email):
        conn.close()
        return jsonify({"error": "Неверный формат email"}), 400

    success = add_email(conn, email)
    conn.close()

    if success:
        return jsonify({"message": "Успешная подписка"}), 200
    return jsonify({"error": "Email уже существует"}), 409

@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    from db.feedbacks_create import create_connection as create_feedback_connection, add_feedback  # Импорт внутри функции
    conn = create_feedback_connection()
    if not conn:
        return jsonify({"error": "Database error"}), 500

    data = {
        'name': request.form.get('name'),
        'email': request.form.get('email'),
        'phone': request.form.get('phone'),
        'message': request.form.get('message')
    }

    if not data['message'] or len(data['message']) < 10:
        conn.close()
        return jsonify({"error": "Сообщение должно содержать минимум 10 символов"}), 400

    success = add_feedback(conn, data)
    conn.close()

    if success:
        return jsonify({"message": "Фидбек успешно отправлен"}), 200
    return jsonify({"error": "Ошибка сохранения"}), 500

# -------------------- Главная страница (для примера) --------------------

@app.route('/')
def index():
    news_list = News.query.filter(News.is_published == True).all() # Получаем все опубликованные новости
    return render_template('index.html', news=news_list)  # Передаем новости в шаблон

# -------------------- Slugify function --------------------
def slugify(text):
    text = text.lower()
    text = re.sub(r'\s+', '-', text)
    text = re.sub(r'[^\w\-]+', '', text)
    return text

@app.route('/news/<slug>')
def view_news(slug):
    news_item = News.query.filter_by(slug=slug).first_or_404() # Получаем новость по slug или возвращаем 404
    return render_template('view_news.html', news_item=news_item)

# -------------------- Admin Required Decorator --------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# -------------------- Admin Panel Routes --------------------
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    news_list = News.query.all() # Получаем все новости из базы данных
    return render_template('admin_panel.html', news=news_list)

@app.route('/admin/news/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_news():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        slug = slugify(title)

        new_news = News(title=title, content=content, author=current_user, slug=slug)
        db.session.add(new_news)
        db.session.commit()
        flash('Новость успешно добавлена!', 'success')
        return redirect(url_for('admin_panel'))

    return render_template('add_news.html')

# -------------------- CORS configuration --------------------
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# -------------------- Запуск приложения --------------------

if __name__ == '__main__':
    with app.app_context(): # Необходимо для создания таблиц вне контекста запроса
        db.create_all()
    app.run(debug=True, port=5000)