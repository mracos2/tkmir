# db/feedbacks_create.py
import sqlite3
from sqlite3 import Error

DATABASE_NAME = 'db/feedbacks.db'  # Относительный путь к базе данных

def create_connection():
    """Создает подключение к базе feedback.db"""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        return conn
    except Error as e:
        print(f"Ошибка подключения: {e}")
    return conn

def create_table(conn):
    """Создает таблицу feedbacks"""
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                name TEXT,
                email TEXT,
                phone TEXT,
                message TEXT NOT NULL
            )
        ''')
        conn.commit()
        print("Таблица feedbacks создана")
    except Error as e:
        print(f"Ошибка: {e}")

def add_feedback(conn, data):
    """Добавляет запись в таблицу"""
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO feedbacks (name, email, phone, message)
            VALUES (?, ?, ?, ?)
        ''', (data['name'], data['email'], data['phone'], data['message']))
        conn.commit()
        return True
    except Error as e:
        print(f"Ошибка: {e}")
        return False

# Инициализация БД
if __name__ == '__main__':
    conn = create_connection()
    if conn:
        create_table(conn)
        conn.close()