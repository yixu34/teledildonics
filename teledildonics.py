from datetime import datetime
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from flask import Flask, request, session, url_for, redirect, render_template, abort, g, flash, _app_ctx_stack
from werkzeug import check_password_hash, generate_password_hash
app = Flask(__name__)
app.config.from_object(__name__)

DEBUG = True
DATABASE = 'teledildonics.db'
SECRET_KEY = 'development key'

def get_db():
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(DATABASE)
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def get_user_id(username):
    rv = query_db('select id from users where name = ?', [username], one=True)
    return rv[0] if rv else None

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from users where id = ?',
                [session['user_id']], one=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('orders', user_id=g.user['id']))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            db = get_db()
            db.execute('''insert into users (name, email, pw_hash) values (?, ?, ?)''',
                    [request.form['username'], request.form['email'],
                    generate_password_hash(request.form['password'])])
            db.commit()
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('orders', user_id=g.user['id']))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from users where name =?''', [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'], request.form['password']):
            error = 'Invalid password'
        else:
            session['user_id'] = user['id']
            return redirect(url_for('orders', user_id=user['id']))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/place_order', methods=['POST'])
def place_order():
    if 'user_id' not in session:
        abort(401)
    db = get_db()
    db.execute('''insert into orders (user_id, item_name) values (?, ?)''',
            (session['user_id'], request.form['item_name']))
    db.commit()
    return redirect(url_for('orders', user_id=session['user_id']))

@app.route('/orders/<user_id>', methods=['GET', 'POST'])
def orders(user_id):
    if request.method == 'POST':
        db = get_db()
        db.execute('''insert into orders (user_id, item_name) values (?, ?)''',
                (session['user_id'], request.form['item_name']))
        db.commit()
        return redirect(url_for('orders', user_id=user_id))

    orders = query_db('''select * from orders where orders.user_id = ?''', [user_id])
    return render_template('orders.html', orders=orders)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.debug = True
    app.secret_key = SECRET_KEY
    app.run()
