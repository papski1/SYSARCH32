from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a random secret key

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS reservations
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  date TEXT NOT NULL,
                  time TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def dashboard():
    if 'username' in session:
        return render_template('sections/dashboard.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    # Assuming user data is stored in session after login
    user_data = session.get('user_data')
    return render_template('sections/profile.html', user_data=user_data)

@app.route('/info')
def info():
    if 'username' in session:
        return render_template('sections/info.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/announcement')
def announcement():
    if 'username' in session:
        return render_template('sections/announcement.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/remaining_session')
def remaining_session():
    if 'username' in session:
        return render_template('sections/remaining_session.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/sit_in_rules')
def sit_in_rules():
    if 'username' in session:
        return render_template('sections/sit_in_rules.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/lab_rules')
def lab_rules():
    if 'username' in session:
        return render_template('sections/lab_rules.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/sit_in_history')
def sit_in_history():
    if 'username' in session:
        return render_template('sections/sit_in_history.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/reservation', methods=['GET', 'POST'])
def reservation():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        date = request.form['date']
        time = request.form['time']
        username = session['username']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO reservations (username, date, time) VALUES (?, ?, ?)', (username, date, time))
        conn.commit()
        conn.close()
        
        flash('Reservation successful!')
        return redirect(url_for('reservation'))
    
    username = session['username']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT date, time FROM reservations WHERE username = ?', (username,))
    reservations = c.fetchall() 
    conn.close()
    
    return render_template('sections/reservation.html', username=username, reservations=reservations)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        
        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                     (username, password))
            conn.commit()
            conn.close()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)