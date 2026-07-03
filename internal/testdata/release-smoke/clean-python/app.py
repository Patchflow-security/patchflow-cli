from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/users')
def users():
    name = request.args.get('name')
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return 'ok'

if __name__ == '__main__':
    app.run()
