from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.secret_key = 'super-secret-key-change-in-prod'

users = {}  
logs = []   

LOGIN_HTML = '''
<!DOCTYPE html>
<html><head><title>Login System</title></head>
<body>
  <h2>Strict Login & Auth System</h2>
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <ul style="color: red;">{% for message in messages %}<li>{{ message }}</li>{% endfor %}</ul>
    {% endif %}
  {% endwith %}
  <form method="POST">
    Username: <input name="username" required><br><br>
    Password: <input name="password" type="password" required><br><br>
    <button type="submit">Login</button>
  </form>
  <br><a href="/register">Register New User</a> | <a href="/logs">View Login Logs</a>
</body></html>
'''

REGISTER_HTML = '''
<!DOCTYPE html>
<html><head><title>Register</title></head>
<body>
  <h2>Register</h2>
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <ul>{% for message in messages %}<li>{{ message }}</li>{% endfor %}</ul>
    {% endif %}
  {% endwith %}
  <form method="POST">
    Username: <input name="username" required><br><br>
    Password: <input name="password" type="password" required><br><br>
    <button type="submit">Register</button>
  </form>
  <br><a href="/">Back to Login</a>
</body></html>
'''

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html><head><title>Dashboard</title></head>
<body>
  <h2>Protected Dashboard</h2>
  <p>Welcome, {{ username }}! You are authenticated.</p>
  <p><a href="/logs">View All Login Logs</a></p>
  <form method="POST" action="/logout">
    <button type="submit">Logout</button>
  </form>
</body></html>
'''

LOGS_HTML = '''
<!DOCTYPE html>
<html><head><title>Logs</title></head>
<body>
  <h2>All Login Attempts ({{ logs|length }} total)</h2>
  <table border="1">
    <tr><th>Time</th><th>Username</th><th>IP</th><th>Success</th></tr>
    {% for log in logs %}
    <tr>
      <td>{{ log.time }}</td><td>{{ log.username }}</td><td>{{ log.ip }}</td><td>{{ 'Yes' if log.success else 'No' }}</td>
    </tr>
    {% endfor %}
  </table>
  <br><a href="/dashboard">Dashboard</a> | <a href="/">Logout</a>
</body></html>
'''

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip = request.remote_addr
        
        logs.append(type('Log', (), {
            'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'username': username,
            'ip': ip,
            'success': False
        }))
        
        if username in users:
            if check_password_hash(users[username], password):
                session['user'] = username
                logs[-1].success = True  # Update last log
                flash('Login successful!')
                return redirect(url_for('dashboard'))
        
        flash('Invalid credentials')
        return render_template_string(LOGIN_HTML)
    
    return render_template_string(LOGIN_HTML)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            flash('Username exists!')
        else:
            users[username] = generate_password_hash(password)
            flash('Registered! Login now.')
            return redirect(url_for('login'))
    return render_template_string(REGISTER_HTML)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash('Access denied. Login required.')
        return redirect(url_for('login'))
    return render_template_string(DASHBOARD_HTML, username=session['user'], logs=logs)

@app.route('/logs')
def logs():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template_string(LOGS_HTML, logs=logs)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    flash('Logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
