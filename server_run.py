# server_run.py
from flask import Flask, request, jsonify
import re
import sqlite3
from db.emails_create import create_connection as create_email_connection, add_email
from db.feedbacks_create import create_connection as create_feedback_connection, add_feedback

app = Flask(__name__)

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

EMAIL_REGEX = r'^[\w\.-]+@[\w\.-]+\.\w+$'

@app.route('/subscribe', methods=['POST'])
def subscribe():
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)