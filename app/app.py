from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import requests
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    wallet_points = db.Column(db.Integer, default=100)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pads = db.Column(db.Integer, nullable=False)
    points_deducted = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    dispensed = db.Column(db.Boolean, default=False, nullable=False)
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

with app.app_context():
    db.create_all()
    if not Admin.query.first():
        hashed_password = generate_password_hash('adminpass')
        new_admin = Admin(username='admin', password=hashed_password)
        db.session.add(new_admin)
        db.session.commit()

# --- User Routes ---
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('index.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if admin
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            return redirect(url_for('admin_dashboard'))

        # Check if user
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('admin_id', None)
    return redirect(url_for('login'))

@app.route('/buy_pads', methods=['POST'])
def buy_pads():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    try:
        pads_to_buy = int(request.form['pads'])
        if pads_to_buy <= 0:
            raise ValueError
    except (ValueError, KeyError):
        flash('Invalid number of pads.')
        return redirect(url_for('index'))

    points_needed = pads_to_buy * 10
    if user.wallet_points < points_needed:
        flash('Not enough points in your wallet.')
        return redirect(url_for('index'))

    # Deduct points and record transaction
    user.wallet_points -= points_needed
    new_transaction = Transaction(user_id=user.id, pads=pads_to_buy, points_deducted=points_needed)
    db.session.add(new_transaction)
    db.session.commit()

    return redirect(url_for('index'))

# --- API for ESP32 Polling ---
@app.route('/api/dispense_jobs', methods=['GET'])
def dispense_jobs():
    # Find the oldest transaction that has not been dispensed yet
    transaction_to_dispense = db.session.query(Transaction).filter_by(dispensed=False).order_by(Transaction.timestamp.asc()).first()

    if transaction_to_dispense:
        # Mark the transaction as dispensed to avoid processing it again
        transaction_to_dispense.dispensed = True
        db.session.commit()
        
        # Return the number of pads for the ESP32 to dispense
        # The response is a simple string: "pads:<number>"
        return f"pads:{transaction_to_dispense.pads}"
    else:
        # No pending jobs, return "pads:0"
        return "pads:0"


# --- Admin Routes ---
@app.route('/admin')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect(url_for('login'))
    
    users = User.query.all()
    transactions = Transaction.query.order_by(Transaction.timestamp.desc()).all()
    return render_template('admin_dashboard.html', users=users, transactions=transactions)

@app.route('/admin/manage_points', methods=['POST'])
def manage_points():
    if 'admin_id' not in session:
        return redirect(url_for('login'))

    try:
        user_id = int(request.form['user_id'])
        points = int(request.form['points'])
        action = request.form['action']
        
        user = User.query.get(user_id)
        if not user:
            flash('User not found.')
            return redirect(url_for('admin_dashboard'))

        if action == 'add':
            user.wallet_points += points
            flash(f'Added {points} points to {user.username}.')
        elif action == 'deduct':
            if user.wallet_points < points:
                flash(f'Cannot deduct {points}, {user.username} only has {user.wallet_points}.')
            else:
                user.wallet_points -= points
                flash(f'Deducted {points} points from {user.username}.')
        
        db.session.commit()

    except (ValueError, KeyError):
        flash('Invalid form data.')

    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    # Use '0.0.0.0' to make the app accessible on your local network
    app.run(host='0.0.0.0', port=5001, debug=True)
