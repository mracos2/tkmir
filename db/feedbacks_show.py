# db/feedbacks_show.py
import sqlite3
from tabulate import tabulate
import os

DATABASE = 'db/feedbacks.db'
OUTPUT_FILE = 'db/feedbacks.html'  # Файл сохраняется в папку db

def get_feedbacks_from_db():
    """Получает все записи из базы данных feedbacks."""
    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, created_at, name, email, phone, message FROM feedbacks")
        rows = cursor.fetchall()
        return rows
    except sqlite3.Error as e:
        print(f"Ошибка при подключении к базе данных или выполнении запроса: {e}")
        return None
    finally:
        if conn:
            conn.close()

def display_feedbacks_table(feedbacks):
    """Выводит список отзывов в виде HTML-таблицы с переносом строк."""
    if feedbacks:
        headers = ["ID", "Created At", "Name", "Email", "Phone", "Message"]
        html_table = tabulate(feedbacks, headers=headers, tablefmt="html")

        # Добавляем CSS-стили для переноса строк
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
                vertical-align: top; /* Выравнивание по верхнему краю */
            }
            td:nth-child(6) {  /* Для столбца Message */
                word-break: break-word;  /* Перенос длинных слов */
                white-space: normal;    /* Разрешить перенос */
            }
        </style>
        """

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Feedbacks</title>
            {css_styles}
        </head>
        <body>
            {html_table}
        </body>
        </html>
        """
        return html_content
    else:
        return "<p>Нет данных для отображения.</p>"


def main():
    """Основная функция приложения."""
    feedbacks = get_feedbacks_from_db()
    if feedbacks:
        html_output = display_feedbacks_table(feedbacks)
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