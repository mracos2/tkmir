# db/emails_create.py
import sqlite3
from sqlite3 import Error

DATABASE_NAME = 'db/emails.db'  # Относительный путь к базе данных

def create_connection():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        return conn
    except Error as e:
        print(f"Ошибка подключения: {e}")
    return conn

def create_table(conn):
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
    except Error as e:
        print(f"Ошибка создания таблицы: {e}")

def add_email(conn, email):
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO emails (email) VALUES (?)', (email,))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    except Error as e:
        print(f"Ошибка: {e}")
        return False

if __name__ == '__main__':
    conn = create_connection()
    if conn:
        create_table(conn)
        conn.close()