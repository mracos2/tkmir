# db/emails_show.py
import sqlite3
from tabulate import tabulate
import os

DATABASE = 'db/emails.db'
OUTPUT_FILE = 'db/emails.html' # Файл сохраняется в папку db

def get_emails_from_db():
    """Получает все записи из базы данных emails."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, created_at FROM emails")  # Изменено на created_at
        rows = cursor.fetchall()
        return rows
    except sqlite3.Error as e:
        print(f"Ошибка при подключении к базе данных или выполнении запроса: {e}")
        return None
    finally:
        if conn:
            conn.close()


def display_emails_table(emails):
    """Выводит список email адресов в виде HTML-таблицы."""
    if emails:
        headers = ["ID", "Email", "Created At"]  # Изменено название столбца
        html_table = tabulate(emails, headers=headers, tablefmt="html")

        css_styles = """
        <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                border: 1px solid black;
                padding: 8px;
                text-align: left;
            }
        </style>
        """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Emails</title>
            {css_styles}
        </head>
        <body>
            {html_table}
        </body>
        </html>
        """
        return html_content
    else:
        print("Нет данных для отображения.")


def main():
    """Основная функция приложения."""
    emails = get_emails_from_db()
    if emails:
        html_output = display_emails_table(emails)
        try:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f: # Используем OUTPUT_FILE
                f.write(html_output)
            print(f"Таблица сохранена в {OUTPUT_FILE}") # Используем OUTPUT_FILE
        except Exception as e:
            print(f"Ошибка при записи файла: {e}")

    else:
        print("Не удалось получить данные из базы данных.")


if __name__ == "__main__":
    main()