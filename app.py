import sqlite3
import hashlib
import os
import re
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import secrets
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Setup logging for audit trail
logging.basicConfig(
    filename='audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Encryption key for sensitive data
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Database initialization
def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('fintech_app.db')
    cursor = conn.cursor()
    
    # Users table with security features
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_login_attempts INTEGER DEFAULT 0,
            account_locked BOOLEAN DEFAULT 0,
            locked_until TIMESTAMP
        )
    ''')
    
    # Transactions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            encrypted_notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Audit logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # User profiles table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            full_name TEXT,
            phone TEXT,
            address TEXT,
            encrypted_ssn TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Security utility functions
def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def hash_password(password):
    """Hash password using werkzeug.security and generate a random salt for storage compatibility"""
    # generate a random salt (stored for compatibility; werkzeug's hash includes its own salt)
    salt = secrets.token_hex(16)
    password_hash = generate_password_hash(password)
    return password_hash, salt

def verify_password(password, hashed_password):
    """Verify password against hash using werkzeug.security"""
    try:
        return check_password_hash(hashed_password, password)
    except Exception:
        return False
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitize_input(input_string):
    """Sanitize user input to prevent XSS"""
    if not input_string:
        return ""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\']', '', str(input_string))
    return sanitized.strip()

def validate_numeric_input(value, min_val=0, max_val=None):
    """Validate numeric input"""
    try:
        num_val = float(value)
        if num_val < min_val:
            return False, f"Value must be at least {min_val}"
        if max_val and num_val > max_val:
            return False, f"Value must not exceed {max_val}"
        return True, num_val
    except (ValueError, TypeError):
        return False, "Invalid numeric value"

def log_audit(user_id, action, details, ip_address):
    """Log user actions for audit trail"""
    try:
        conn = sqlite3.connect('fintech_app.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (user_id, action, details, ip_address))
        conn.commit()
        conn.close()
        
        # Also log to file
        logging.info(f"User {user_id}: {action} - {details} - IP: {ip_address}")
    except Exception as e:
        logging.error(f"Audit logging failed: {str(e)}")

def encrypt_data(data):
    """Encrypt sensitive data"""
    if not data:
        return ""
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Decrypt sensitive data"""
    if not encrypted_data:
        return ""
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except:
        return "Decryption failed"

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def check_session_timeout():
    """Check if session has timed out"""
    if 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.now() - last_activity > timedelta(minutes=30):
            session.clear()
            return True
    return False

def update_session_activity():
    """Update last activity timestamp"""
    session['last_activity'] = datetime.now().isoformat()

# Route handlers
@app.before_request
def before_request():
    """Check session timeout before each request"""
    if request.endpoint not in ['login', 'register', 'static'] and 'user_id' in session:
        if check_session_timeout():
            flash('Session expired. Please login again.', 'warning')
            return redirect(url_for('login'))
        update_session_activity()

@app.route('/')
def index():
    """Home page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with security validation"""
    if request.method == 'POST':
        try:
            username = sanitize_input(request.form.get('username', ''))
            email = sanitize_input(request.form.get('email', ''))
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Input validation
            if not username or len(username) < 3:
                flash('Username must be at least 3 characters long', 'error')
                return render_template('register.html')
            
            if len(username) > 50:
                flash('Username too long', 'error')
                return render_template('register.html')
            
            if not validate_email(email):
                flash('Invalid email format', 'error')
                return render_template('register.html')
            
            # Password validation
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, 'error')
                return render_template('register.html')
            
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('register.html')
            
            # Check for existing user
            conn = sqlite3.connect('fintech_app.db')
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if cursor.fetchone():
                flash('Username or email already exists', 'error')
                conn.close()
                return render_template('register.html')
            
            # Hash password and create user
            password_hash, salt = hash_password(password)
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, salt)
                VALUES (?, ?, ?, ?)
            ''', (username, email, password_hash, salt))
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Log registration
            log_audit(user_id, 'USER_REGISTERED', f'New user registered: {username}', request.remote_addr)
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login with brute force protection"""
    if request.method == 'POST':
        try:
            username = sanitize_input(request.form.get('username', ''))
            password = request.form.get('password', '')
            
            if not username or not password:
                flash('Username and password are required', 'error')
                return render_template('login.html')
            
            conn = sqlite3.connect('fintech_app.db')
            cursor = conn.cursor()
            
            # Check user exists and account status
            cursor.execute('''
                SELECT id, username, password_hash, failed_login_attempts, account_locked, locked_until
                FROM users WHERE username = ?
            ''', (username,))
            user = cursor.fetchone()
            
            if not user:
                flash('Invalid username or password', 'error')
                log_audit(None, 'LOGIN_FAILED', f'Failed login attempt for non-existent user: {username}', request.remote_addr)
                return render_template('login.html')
            
            user_id, db_username, password_hash, failed_attempts, account_locked, locked_until = user
            
            # Check if account is locked
            if account_locked and locked_until:
                locked_until_dt = datetime.fromisoformat(locked_until)
                if datetime.now() < locked_until_dt:
                    flash('Account is locked due to multiple failed login attempts. Try again later.', 'error')
                    return render_template('login.html')
                else:
                    # Unlock account
                    cursor.execute('''
                        UPDATE users SET account_locked = 0, locked_until = NULL, failed_login_attempts = 0
                        WHERE id = ?
                    ''', (user_id,))
                    conn.commit()
            
            # Verify password
            if verify_password(password, password_hash):
                # Successful login
                cursor.execute('''
                    UPDATE users SET last_login = ?, failed_login_attempts = 0
                    WHERE id = ?
                ''', (datetime.now(), user_id))
                conn.commit()
                
                session['user_id'] = user_id
                session['username'] = db_username
                update_session_activity()
                
                log_audit(user_id, 'LOGIN_SUCCESS', 'User logged in successfully', request.remote_addr)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Failed login
                failed_attempts += 1
                if failed_attempts >= 5:
                    # Lock account for 15 minutes
                    locked_until = datetime.now() + timedelta(minutes=15)
                    cursor.execute('''
                        UPDATE users SET failed_login_attempts = ?, account_locked = 1, locked_until = ?
                        WHERE id = ?
                    ''', (failed_attempts, locked_until, user_id))
                    flash('Account locked due to multiple failed attempts. Try again in 15 minutes.', 'error')
                else:
                    cursor.execute('''
                        UPDATE users SET failed_login_attempts = ?
                        WHERE id = ?
                    ''', (failed_attempts, user_id))
                    remaining = 5 - failed_attempts
                    flash(f'Invalid password. {remaining} attempts remaining.', 'error')
                
                conn.commit()
                log_audit(user_id, 'LOGIN_FAILED', f'Failed login attempt {failed_attempts}', request.remote_addr)
            
            conn.close()
            
        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            flash('Login failed. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """User dashboard - requires authentication"""
    if 'user_id' not in session:
        flash('Please login to access dashboard', 'warning')
        return redirect(url_for('login'))
    
    try:
        conn = sqlite3.connect('fintech_app.db')
        cursor = conn.cursor()
        
        # Get user's recent transactions
        cursor.execute('''
            SELECT id, transaction_type, amount, description, created_at
            FROM transactions
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 10
        ''', (session['user_id'],))
        transactions = cursor.fetchall()
        
        # Get account balance (sum of all transactions)
        cursor.execute('''
            SELECT SUM(CASE WHEN transaction_type = 'deposit' THEN amount ELSE -amount END) as balance
            FROM transactions
            WHERE user_id = ?
        ''', (session['user_id'],))
        balance_result = cursor.fetchone()
        balance = balance_result[0] if balance_result[0] else 0.0
        
        conn.close()
        
        log_audit(session['user_id'], 'DASHBOARD_ACCESS', 'User accessed dashboard', request.remote_addr)
        
        return render_template('dashboard.html', 
                             username=session['username'],
                             transactions=transactions,
                             balance=balance)
    except Exception as e:
        logging.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/transaction', methods=['GET', 'POST'])
def transaction():
    """Add new transaction with input validation"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            transaction_type = sanitize_input(request.form.get('transaction_type', ''))
            amount_str = request.form.get('amount', '')
            description = sanitize_input(request.form.get('description', ''))
            notes = request.form.get('notes', '')
            
            # Validate transaction type
            if transaction_type not in ['deposit', 'withdrawal']:
                flash('Invalid transaction type', 'error')
                return render_template('transaction.html')
            
            # Validate amount
            is_valid, amount = validate_numeric_input(amount_str, min_val=0.01, max_val=1000000)
            if not is_valid:
                flash(f'Invalid amount: {amount}', 'error')
                return render_template('transaction.html')
            
            # Validate description length
            if len(description) > 200:
                flash('Description too long (max 200 characters)', 'error')
                return render_template('transaction.html')
            
            # Encrypt sensitive notes
            encrypted_notes = encrypt_data(notes) if notes else ''
            
            # Add transaction
            conn = sqlite3.connect('fintech_app.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO transactions (user_id, transaction_type, amount, description, encrypted_notes)
                VALUES (?, ?, ?, ?, ?)
            ''', (session['user_id'], transaction_type, amount, description, encrypted_notes))
            conn.commit()
            conn.close()
            
            log_audit(session['user_id'], 'TRANSACTION_ADDED', 
                     f'{transaction_type.title()} of ${amount:.2f}', request.remote_addr)
            
            flash(f'{transaction_type.title()} of ${amount:.2f} added successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logging.error(f"Transaction error: {str(e)}")
            flash('Transaction failed. Please try again.', 'error')
    
    return render_template('transaction.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """User profile management with validation"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            full_name = sanitize_input(request.form.get('full_name', ''))
            phone = sanitize_input(request.form.get('phone', ''))
            address = sanitize_input(request.form.get('address', ''))
            ssn = request.form.get('ssn', '')
            
            # Validate inputs
            if full_name and len(full_name) > 100:
                flash('Full name too long', 'error')
                return render_template('profile.html')
            
            if phone and not re.match(r'^\+?[\d\s\-\(\)]{10,15}$', phone):
                flash('Invalid phone number format', 'error')
                return render_template('profile.html')
            
            if address and len(address) > 200:
                flash('Address too long', 'error')
                return render_template('profile.html')
            
            # Encrypt SSN if provided
            encrypted_ssn = encrypt_data(ssn) if ssn else ''
            
            conn = sqlite3.connect('fintech_app.db')
            cursor = conn.cursor()
            
            # Check if profile exists
            cursor.execute('SELECT id FROM user_profiles WHERE user_id = ?', (session['user_id'],))
            if cursor.fetchone():
                # Update existing profile
                cursor.execute('''
                    UPDATE user_profiles 
                    SET full_name = ?, phone = ?, address = ?, encrypted_ssn = ?, updated_at = ?
                    WHERE user_id = ?
                ''', (full_name, phone, address, encrypted_ssn, datetime.now(), session['user_id']))
            else:
                # Create new profile
                cursor.execute('''
                    INSERT INTO user_profiles (user_id, full_name, phone, address, encrypted_ssn)
                    VALUES (?, ?, ?, ?, ?)
                ''', (session['user_id'], full_name, phone, address, encrypted_ssn))
            
            conn.commit()
            conn.close()
            
            log_audit(session['user_id'], 'PROFILE_UPDATED', 'User profile updated', request.remote_addr)
            flash('Profile updated successfully!', 'success')
            
        except Exception as e:
            logging.error(f"Profile update error: {str(e)}")
            flash('Profile update failed. Please try again.', 'error')
    
    # Load existing profile
    try:
        conn = sqlite3.connect('fintech_app.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT full_name, phone, address, encrypted_ssn
            FROM user_profiles WHERE user_id = ?
        ''', (session['user_id'],))
        profile_data = cursor.fetchone()
        conn.close()
        
        if profile_data:
            full_name, phone, address, encrypted_ssn = profile_data
            # Decrypt SSN for display (masked)
            ssn = decrypt_data(encrypted_ssn) if encrypted_ssn else ''
            if ssn and len(ssn) >= 4:
                ssn = 'XXX-XX-' + ssn[-4:]  # Mask SSN
        else:
            full_name = phone = address = ssn = ''
            
        return render_template('profile.html', 
                             full_name=full_name, phone=phone, 
                             address=address, ssn=ssn)
    except Exception as e:
        logging.error(f"Profile load error: {str(e)}")
        return render_template('profile.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """File upload with validation"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file selected', 'error')
                return render_template('upload.html')
            
            file = request.files['file']
            if file.filename == '':
                flash('No file selected', 'error')
                return render_template('upload.html')
            
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add timestamp to avoid conflicts
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                filename = timestamp + filename
                
                # Check file size (additional validation)
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                
                if file_size > app.config['MAX_CONTENT_LENGTH']:
                    flash('File too large', 'error')
                    return render_template('upload.html')
                
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                log_audit(session['user_id'], 'FILE_UPLOADED', 
                         f'File uploaded: {filename} ({file_size} bytes)', request.remote_addr)
                
                flash(f'File {filename} uploaded successfully!', 'success')
            else:
                flash('Invalid file type. Allowed: txt, pdf, png, jpg, jpeg, gif', 'error')
                
        except Exception as e:
            logging.error(f"File upload error: {str(e)}")
            flash('File upload failed. Please try again.', 'error')
    
    return render_template('upload.html')

@app.route('/audit')
def audit_logs():
    """View audit logs (admin feature)"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = sqlite3.connect('fintech_app.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT action, details, ip_address, timestamp
            FROM audit_logs
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT 50
        ''', (session['user_id'],))
        logs = cursor.fetchall()
        conn.close()
        
        log_audit(session['user_id'], 'AUDIT_ACCESSED', 'User viewed audit logs', request.remote_addr)
        
        return render_template('audit.html', logs=logs)
    except Exception as e:
        logging.error(f"Audit view error: {str(e)}")
        flash('Error loading audit logs', 'error')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    """Secure logout"""
    user_id = session.get('user_id')
    if user_id:
        log_audit(user_id, 'LOGOUT', 'User logged out', request.remote_addr)
    
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors securely"""
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors securely"""
    logging.error(f"Internal server error: {str(error)}")
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.errorhandler(413)
def file_too_large(error):
    """Handle file too large errors"""
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(url_for('upload_file'))

# Initialize database on startup
if __name__ == '__main__':
    init_db()
    
    # Create templates directory and basic templates
    os.makedirs('templates', exist_ok=True)
    
    # Create basic HTML templates
    templates = {
        'base.html': '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}SecureFinTech Pro{% endblock %}</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #2563eb;
            --primary-dark: #1d4ed8;
            --secondary-color: #64748b;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --error-color: #ef4444;
            --background: #f8fafc;
            --card-bg: #ffffff;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --border-color: #e2e8f0;
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: var(--text-primary);
            line-height: 1.6;
        }

        .main-container {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--border-color);
            padding: 1rem 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--primary-color);
            text-decoration: none;
        }

        .logo i {
            font-size: 2rem;
            background: linear-gradient(135deg, var(--primary-color), #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .nav-menu {
            display: flex;
            gap: 2rem;
            align-items: center;
        }

        .nav-link {
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 500;
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .nav-link:hover {
            color: var(--primary-color);
            background: rgba(37, 99, 235, 0.1);
        }

        .nav-link.active {
            color: var(--primary-color);
            background: rgba(37, 99, 235, 0.1);
        }

        .user-menu {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-avatar {
            width: 2.5rem;
            height: 2.5rem;
            border-radius: 50%;
            background: var(--primary-color);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
        }

        .container {
            flex: 1;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            width: 100%;
        }

        .auth-container {
            max-width: 450px;
            margin: 0 auto;
            padding: 2rem;
        }

        .card {
            background: var(--card-bg);
            border-radius: 1rem;
            box-shadow: var(--shadow-lg);
            padding: 2rem;
            border: 1px solid var(--border-color);
        }

        .auth-card {
            text-align: center;
            padding: 3rem;
        }

        .auth-header {
            margin-bottom: 2rem;
        }

        .auth-title {
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }

        .auth-subtitle {
            color: var(--text-secondary);
            font-size: 1rem;
        }

        .form-group {
            margin-bottom: 1.5rem;
            text-align: left;
        }

        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--text-primary);
        }

        .input-wrapper {
            position: relative;
        }

        .form-input {
            width: 100%;
            padding: 0.875rem 1rem;
            border: 2px solid var(--border-color);
            border-radius: 0.5rem;
            font-size: 1rem;
            transition: all 0.2s;
            background: white;
        }

        .form-input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .form-input.error {
            border-color: var(--error-color);
        }

        .password-input {
            padding-right: 3rem;
        }

        .password-toggle {
            position: absolute;
            right: 1rem;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 1.1rem;
            transition: color 0.2s;
        }

        .password-toggle:hover {
            color: var(--primary-color);
        }

        .form-help {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0.875rem 1.5rem;
            border: none;
            border-radius: 0.5rem;
            font-size: 1rem;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.2s;
            min-width: 120px;
        }

        .btn-primary {
            background: var(--primary-color);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
            box-shadow: var(--shadow);
        }

        .btn-secondary {
            background: var(--background);
            color: var(--text-primary);
            border: 2px solid var(--border-color);
        }

        .btn-secondary:hover {
            background: var(--border-color);
        }

        .btn-danger {
            background: var(--error-color);
            color: white;
        }

        .btn-danger:hover {
            background: #dc2626;
        }

        .btn-full {
            width: 100%;
        }

        .btn-group {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .alert {
            padding: 1rem 1.25rem;
            border-radius: 0.5rem;
            margin-bottom: 1.5rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            color: #065f46;
            border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .alert-error {
            background: rgba(239, 68, 68, 0.1);
            color: #991b1b;
            border: 1px solid rgba(239, 68, 68, 0.2);
        }

        .alert-warning {
            background: rgba(245, 158, 11, 0.1);
            color: #92400e;
            border: 1px solid rgba(245, 158, 11, 0.2);
        }

        .alert-info {
            background: rgba(37, 99, 235, 0.1);
            color: #1e40af;
            border: 1px solid rgba(37, 99, 235, 0.2);
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .stats-card {
            background: var(--card-bg);
            border-radius: 1rem;
            padding: 2rem;
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            position: relative;
            overflow: hidden;
        }

        .stats-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-color), #8b5cf6);
        }

        .stats-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .stats-title {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .stats-icon {
            width: 3rem;
            height: 3rem;
            border-radius: 0.75rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            color: white;
        }

        .stats-icon.balance {
            background: linear-gradient(135deg, #10b981, #059669);
        }

        .stats-icon.transactions {
            background: linear-gradient(135deg, #3b82f6, #2563eb);
        }

        .stats-icon.activity {
            background: linear-gradient(135deg, #8b5cf6, #7c3aed);
        }

        .stats-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }

        .stats-label {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }

        .table-container {
            background: var(--card-bg);
            border-radius: 1rem;
            box-shadow: var(--shadow);
            overflow: hidden;
            border: 1px solid var(--border-color);
        }

        .table-header {
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border-color);
            background: var(--background);
        }

        .table-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .table {
            width: 100%;
            border-collapse: collapse;
        }

        .table th,
        .table td {
            padding: 1rem 2rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .table th {
            background: var(--background);
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .table tbody tr:hover {
            background: var(--background);
        }

        .badge {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .badge-success {
            background: rgba(16, 185, 129, 0.1);
            color: #065f46;
        }

        .badge-danger {
            background: rgba(239, 68, 68, 0.1);
            color: #991b1b;
        }

        .badge-warning {
            background: rgba(245, 158, 11, 0.1);
            color: #92400e;
        }

        .empty-state {
            text-align: center;
            padding: 3rem 2rem;
            color: var(--text-secondary);
        }

        .empty-state i {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        .footer {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-top: 1px solid var(--border-color);
            padding: 2rem 0;
            margin-top: 4rem;
        }

        .footer-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            text-align: center;
            color: var(--text-secondary);
        }

        .password-strength {
            margin-top: 0.5rem;
            padding: 0.75rem;
            border-radius: 0.5rem;
            background: var(--background);
            border: 1px solid var(--border-color);
        }

        .strength-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            margin-bottom: 0.25rem;
        }

        .strength-item:last-child {
            margin-bottom: 0;
        }

        .strength-check {
            color: var(--success-color);
        }

        .strength-cross {
            color: var(--error-color);
        }

        @media (max-width: 768px) {
            .header-content {
                padding: 0 1rem;
            }

            .nav-menu {
                gap: 1rem;
            }

            .nav-link {
                padding: 0.5rem;
                font-size: 0.875rem;
            }

            .container {
                padding: 1rem;
            }

            .auth-card {
                padding: 2rem 1.5rem;
            }

            .dashboard-grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }

            .table th,
            .table td {
                padding: 0.75rem 1rem;
                font-size: 0.875rem;
            }
        }

        .loading {
            position: relative;
            pointer-events: none;
        }

        .loading::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 1rem;
            height: 1rem;
            margin: -0.5rem 0 0 -0.5rem;
            border: 2px solid transparent;
            border-top: 2px solid currentColor;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to {
                transform: rotate(360deg);
            }
        }

        .notification {
            position: fixed;
            top: 2rem;
            right: 2rem;
            max-width: 400px;
            z-index: 1000;
            animation: slideIn 0.3s ease-out;
        }

        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
    </style>
</head>
<body>
    <div class="main-container">
        <header class="header">
            <div class="header-content">
                <a href="{{ url_for('index') }}" class="logo">
                    <i class="fas fa-shield-alt"></i>
                    SecureFinTech Pro
                </a>
                
                {% if session.user_id %}
                <nav class="nav-menu">
                    <a href="{{ url_for('dashboard') }}" class="nav-link">
                        <i class="fas fa-chart-line"></i>
                        Dashboard
                    </a>
                    <a href="{{ url_for('transaction') }}" class="nav-link">
                        <i class="fas fa-plus-circle"></i>
                        Transaction
                    </a>
                    <a href="{{ url_for('profile') }}" class="nav-link">
                        <i class="fas fa-user-cog"></i>
                        Profile
                    </a>
                    <a href="{{ url_for('upload_file') }}" class="nav-link">
                        <i class="fas fa-cloud-upload-alt"></i>
                        Upload
                    </a>
                    <a href="{{ url_for('audit_logs') }}" class="nav-link">
                        <i class="fas fa-clipboard-list"></i>
                        Audit
                   
                </nav>
                
                <div class="user-menu">
                    <div class="user-avatar">
                        {{ session.username[0].upper() if session.username else 'U' }}
                    </div>
                    <a href="{{ url_for('logout') }}" class="btn btn-danger">
                        <i class="fas fa-sign-out-alt"></i>
                        Logout
                    </a>
                </div>
                {% endif %}
            </div>
        </header>

        <main class="container">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">
                            <i class="fas fa-{{ 'check-circle' if category == 'success' else 'exclamation-triangle' if category == 'warning' else 'times-circle' if category == 'error' else 'info-circle' }}"></i>
                            {{ message }}
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            {% block content %}{% endblock %}
        </main>

        <footer class="footer">
            <div class="footer-content">
                <p>&copy; 2024 SecureFinTech Pro. Built with security in mind.</p>
            </div>
        </footer>
    </div>

    <script>
        // Password toggle functionality
        function togglePassword(inputId, toggleBtn) {
            const input = document.getElementById(inputId);
            const icon = toggleBtn.querySelector('i');
            
            if (input.type === 'password') {
                input.type = 'text';
                icon.className = 'fas fa-eye-slash';
            } else {
                input.type = 'password';
                icon.className = 'fas fa-eye';
            }
        }

        // Password strength checker
        function checkPasswordStrength(password) {
            const checks = {
                length: password.length >= 8,
                uppercase: /[A-Z]/.test(password),
                lowercase: /[a-z]/.test(password),
                number: /\d/.test(password),
                special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
            };

            return checks;
        }

        // Real-time password strength display
        document.addEventListener('DOMContentLoaded', function() {
            const passwordInput = document.getElementById('password');
            const strengthIndicator = document.getElementById('password-strength');
            
            if (passwordInput && strengthIndicator) {
                passwordInput.addEventListener('input', function() {
                    const password = this.value;
                    const checks = checkPasswordStrength(password);
                    
                    strengthIndicator.innerHTML = `
                        <div class="strength-item">
                            <i class="fas fa-${checks.length ? 'check' : 'times'} strength-${checks.length ? 'check' : 'cross'}"></i>
                            At least 8 characters
                        </div>
                        <div class="strength-item">
                            <i class="fas fa-${checks.uppercase ? 'check' : 'times'} strength-${checks.uppercase ? 'check' : 'cross'}"></i>
                            One uppercase letter
                        </div>
                        <div class="strength-item">
                            <i class="fas fa-${checks.lowercase ? 'check' : 'times'} strength-${checks.lowercase ? 'check' : 'cross'}"></i>
                            One lowercase letter
                        </div>
                        <div class="strength-item">
                            <i class="fas fa-${checks.number ? 'check' : 'times'} strength-${checks.number ? 'check' : 'cross'}"></i>
                            One number
                        </div>
                        <div class="strength-item">
                            <i class="fas fa-${checks.special ? 'check' : 'times'} strength-${checks.special ? 'check' : 'cross'}"></i>
                            One special character
                        </div>
                    `;
                });
            }
        });

        // Form loading states
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', function() {
                const submitBtn = this.querySelector('button[type="submit"]');
                if (submitBtn) {
                    submitBtn.classList.add('loading');
                    submitBtn.disabled = true;
                }
            });
        });

        // Auto-hide alerts after 5 seconds
        document.querySelectorAll('.alert').forEach(alert => {
            setTimeout(() => {
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-20px)';
                setTimeout(() => alert.remove(), 300);
            }, 5000);
        });
    </script>
</body>
</html>''',
        
        'login.html': '''{% extends "base.html" %}
{% block title %}Login - SecureFinTech Pro{% endblock %}
{% block content %}
<div class="auth-container">
    <div class="card auth-card">
        <div class="auth-header">
            <h1 class="auth-title">Welcome Back</h1>
            <p class="auth-subtitle">Sign in to your secure account</p>
        </div>
        
        <form method="POST">
            <div class="form-group">
                <label for="username" class="form-label">
                    <i class="fas fa-user"></i>
                    Username
                </label>
                <input type="text" id="username" name="username" class="form-input" required maxlength="50" autocomplete="username">
            </div>
            
            <div class="form-group">
                <label for="password" class="form-label">
                    <i class="fas fa-lock"></i>
                    Password
                </label>
                <div class="input-wrapper">
                    <input type="password" id="password" name="password" class="form-input password-input" required autocomplete="current-password">
                    <button type="button" class="password-toggle" onclick="togglePassword('password', this)">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
            
            <button type="submit" class="btn btn-primary btn-full">
                <i class="fas fa-sign-in-alt"></i>
                Sign In
            </button>
            
            <div style="text-align: center; margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border-color);">
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">Don't have an account?</p>
                <a href="{{ url_for('register') }}" class="btn btn-secondary">
                    <i class="fas fa-user-plus"></i>
                    Create Account
                </a>
            </div>
        </form>
    </div>
</div>
{% endblock %}''',
        
        'register.html': '''{% extends "base.html" %}
{% block title %}Register - SecureFinTech Pro{% endblock %}
{% block content %}
<div class="auth-container">
    <div class="card auth-card">
        <div class="auth-header">
            <h1 class="auth-title">Create Account</h1>
            <p class="auth-subtitle">Join SecureFinTech Pro today</p>
        </div>
        
        <form method="POST">
            <div class="form-group">
                <label for="username" class="form-label">
                    <i class="fas fa-user"></i>
                    Username
                </label>
                <input type="text" id="username" name="username" class="form-input" required minlength="3" maxlength="50" autocomplete="username">
                <div class="form-help">3-50 characters, letters and numbers only</div>
            </div>
            
            <div class="form-group">
                <label for="email" class="form-label">
                    <i class="fas fa-envelope"></i>
                    Email Address
                </label>
                <input type="email" id="email" name="email" class="form-input" required autocomplete="email">
            </div>
            
            <div class="form-group">
                <label for="password" class="form-label">
                    <i class="fas fa-lock"></i>
                    Password
                </label>
                <div class="input-wrapper">
                    <input type="password" id="password" name="password" class="form-input password-input" required autocomplete="new-password">
                    <button type="button" class="password-toggle" onclick="togglePassword('password', this)">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
                <div id="password-strength" class="password-strength" style="display: none;"></div>
            </div>
            
            <div class="form-group">
                <label for="confirm_password" class="form-label">
                    <i class="fas fa-lock"></i>
                    Confirm Password
                </label>
                <div class="input-wrapper">
                    <input type="password" id="confirm_password" name="confirm_password" class="form-input password-input" required autocomplete="new-password">
                    <button type="button" class="password-toggle" onclick="togglePassword('confirm_password', this)">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
            
            <button type="submit" class="btn btn-primary btn-full">
                <i class="fas fa-user-plus"></i>
                Create Account
            </button>
            
            <div style="text-align: center; margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border-color);">
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">Already have an account?</p>
                <a href="{{ url_for('login') }}" class="btn btn-secondary">
                    <i class="fas fa-sign-in-alt"></i>
                    Sign In
                </a>
            </div>
        </form>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password');
    const strengthIndicator = document.getElementById('password-strength');
    
    passwordInput.addEventListener('focus', function() {
        strengthIndicator.style.display = 'block';
    });
    
    passwordInput.addEventListener('input', function() {
        const password = this.value;
        if (password.length === 0) {
            strengthIndicator.style.display = 'none';
            return;
        }
        
        const checks = checkPasswordStrength(password);
        
        strengthIndicator.innerHTML = `
            <div class="strength-item">
                <i class="fas fa-${checks.length ? 'check' : 'times'} strength-${checks.length ? 'check' : 'cross'}"></i>
                At least 8 characters
            </div>
            <div class="strength-item">
                <i class="fas fa-${checks.uppercase ? 'check' : 'times'} strength-${checks.uppercase ? 'check' : 'cross'}"></i>
                One uppercase letter
            </div>
            <div class="strength-item">
                <i class="fas fa-${checks.lowercase ? 'check' : 'times'} strength-${checks.lowercase ? 'check' : 'cross'}"></i>
                One lowercase letter
            </div>
            <div class="strength-item">
                <i class="fas fa-${checks.number ? 'check' : 'times'} strength-${checks.number ? 'check' : 'cross'}"></i>
                One number
            </div>
            <div class="strength-item">
                <i class="fas fa-${checks.special ? 'check' : 'times'} strength-${checks.special ? 'check' : 'cross'}"></i>
                One special character
            </div>
        `;
    });
});
</script>
{% endblock %}''',
        
        'dashboard.html': '''{% extends "base.html" %}
{% block title %}Dashboard - SecureFinTech Pro{% endblock %}
{% block content %}
<div style="margin-bottom: 2rem;">
    <h1 style="font-size: 2.5rem; font-weight: 700; color: var(--text-primary); margin-bottom: 0.5rem;">
        Welcome back, {{ username }}!
    </h1>
    <p style="color: var(--text-secondary); font-size: 1.125rem;">
        Here's your financial overview for today
    </p>
</div>

<div class="dashboard-grid">
    <div class="stats-card">
        <div class="stats-header">
            <div class="stats-title">Account Balance</div>
            <div class="stats-icon balance">
                <i class="fas fa-wallet"></i>
            </div>
        </div>
        <div class="stats-value">${{ "%.2f"|format(balance) }}</div>
        <div class="stats-label">Current balance</div>
    </div>
    
    <div class="stats-card">
        <div class="stats-header">
            <div class="stats-title">Total Transactions</div>
            <div class="stats-icon transactions">
                <i class="fas fa-exchange-alt"></i>
            </div>
        </div>
        <div class="stats-value">{{ transactions|length }}</div>
        <div class="stats-label">This month</div>
    </div>
    
    <div class="stats-card">
        <div class="stats-header">
            <div class="stats-title">Account Status</div>
            <div class="stats-icon activity">
                <i class="fas fa-shield-check"></i>
            </div>
        </div>
        <div class="stats-value">
            <span class="badge badge-success">Active</span>
        </div>
        <div class="stats-label">Security verified</div>
    </div>
</div>

<div class="table-container">
    <div class="table-header">
        <h2 class="table-title">
            <i class="fas fa-history"></i>
            Recent Transactions
        </h2>
    </div>
    
    {% if transactions %}
    <table class="table">
        <thead>
            <tr>
                <th>Type</th>
                <th>Amount</th>
                <th>Description</th>
                <th>Date</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {% for transaction in transactions %}
            <tr>
                <td>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <i class="fas fa-{{ 'arrow-up' if transaction[1] == 'deposit' else 'arrow-down' }}" 
                           style="color: {{ 'var(--success-color)' if transaction[1] == 'deposit' else 'var(--error-color)' }};"></i>
                        {{ transaction[1].title() }}
                    </div>
                </td>
                <td style="font-weight: 600; color: {{ 'var(--success-color)' if transaction[1] == 'deposit' else 'var(--error-color)' }};">
                    {{ '+' if transaction[1] == 'deposit' else '-' }}${{ "%.2f"|format(transaction[2]) }}
                </td>
                <td>{{ transaction[3] or 'No description' }}</td>
                <td style="color: var(--text-secondary);">{{ transaction[4] }}</td>
                <td>
                    <span class="badge badge-success">
                        <i class="fas fa-check"></i>
                        Completed
                    </span>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="empty-state">
        <i class="fas fa-receipt"></i>
        <h3>No transactions yet</h3>
        <p>Start by adding your first transaction</p>
        <a href="{{ url_for('transaction') }}" class="btn btn-primary" style="margin-top: 1rem;">
            <i class="fas fa-plus"></i>
            Add Transaction
        </a>
    </div>
    {% endif %}
</div>

<div style="margin-top: 2rem; display: flex; gap: 1rem; flex-wrap: wrap;">
    <a href="{{ url_for('transaction') }}" class="btn btn-primary">
        <i class="fas fa-plus-circle"></i>
        New Transaction
    </a>
    <a href="{{ url_for('profile') }}" class="btn btn-secondary">
        <i class="fas fa-user-cog"></i>
        Manage Profile
    </a>
    <a href="{{ url_for('audit_logs') }}" class="btn btn-secondary">
        <i class="fas fa-clipboard-list"></i>
        View Activity
    </a>
</div>
{% endblock %}''',

        'transaction.html': '''{% extends "base.html" %}
{% block title %}New Transaction - SecureFinTech Pro{% endblock %}
{% block content %}
<div style="max-width: 600px; margin: 0 auto;">
    <div class="card">
        <div style="text-align: center; margin-bottom: 2rem;">
            <h1 style="font-size: 2rem; font-weight: 700; color: var(--text-primary); margin-bottom: 0.5rem;">
                <i class="fas fa-plus-circle" style="color: var(--primary-color);"></i>
                New Transaction
            </h1>
            <p style="color: var(--text-secondary);">Add a deposit or withdrawal to your account</p>
        </div>
        
        <form method="POST">
            <div class="form-group">
                <label for="transaction_type" class="form-label">
                    <i class="fas fa-exchange-alt"></i>
                    Transaction Type
                </label>
                <select id="transaction_type" name="transaction_type" class="form-input" required>
                    <option value="">Select transaction type</option>
                    <option value="deposit">Deposit (Add Money)</option>
                    <option value="withdrawal">Withdrawal (Remove Money)</option>
                </select>
            </div>
            
            <div class="form-group">
                <label for="amount" class="form-label">
                    <i class="fas fa-dollar-sign"></i>
                    Amount
                </label>
                <input type="number" id="amount" name="amount" class="form-input" step="0.01" min="0.01" max="1000000" required placeholder="0.00">
                <div class="form-help">Enter amount between $0.01 and $1,000,000</div>
            </div>
            
            <div class="form-group">
                <label for="description" class="form-label">
                    <i class="fas fa-file-alt"></i>
                    Description
                </label>
                <input type="text" id="description" name="description" class="form-input" maxlength="200" placeholder="What's this transaction for?">
                <div class="form-help">Optional - Max 200 characters</div>
            </div>
            
            <div class="form-group">
                <label for="notes" class="form-label">
                    <i class="fas fa-lock"></i>
                    Private Notes (Encrypted)
                </label>
                <textarea id="notes" name="notes" class="form-input" rows="3" placeholder="Add private notes (will be encrypted)"></textarea>
                <div class="form-help">These notes will be encrypted and only visible to you</div>
            </div>
            
            <div class="btn-group">
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-check"></i>
                    Add Transaction
                </button>
                <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">
                    <i class="fas fa-times"></i>
                    Cancel
                </a>
            </div>
        </form>
    </div>
</div>
{% endblock %}''',

        'profile.html': '''{% extends "base.html" %}
{% block title %}Profile - SecureFinTech Pro{% endblock %}
{% block content %}
<div style="max-width: 800px; margin: 0 auto;">
    <div style="text-align: center; margin-bottom: 2rem;">
        <div class="user-avatar" style="width: 5rem; height: 5rem; font-size: 2rem; margin: 0 auto 1rem;">
            {{ session.username[0].upper() if session.username else 'U' }}
        </div>
        <h1 style="font-size: 2rem; font-weight: 700; color: var(--text-primary); margin-bottom: 0.5rem;">
            User Profile
        </h1>
        <p style="color: var(--text-secondary);">Manage your personal information and security settings</p>
    </div>
    
    <div class="card">
        <form method="POST">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
                <div class="form-group">
                    <label for="full_name" class="form-label">
                        <i class="fas fa-user"></i>
                        Full Name
                    </label>
                    <input type="text" id="full_name" name="full_name" class="form-input" value="{{ full_name or '' }}" maxlength="100" placeholder="Enter your full name">
                </div>
                
                <div class="form-group">
                    <label for="phone" class="form-label">
                        <i class="fas fa-phone"></i>
                        Phone Number
                    </label>
                    <input type="tel" id="phone" name="phone" class="form-input" value="{{ phone or '' }}" placeholder="+1 (555) 123-4567">
                </div>
            </div>
            
            <div class="form-group">
                <label for="address" class="form-label">
                    <i class="fas fa-map-marker-alt"></i>
                    Address
                </label>
                <textarea id="address" name="address" class="form-input" rows="3" maxlength="200" placeholder="Enter your address">{{ address or '' }}</textarea>
                <div class="form-help">Max 200 characters</div>
            </div>
            
            <div class="form-group">
                <label for="ssn" class="form-label">
                    <i class="fas fa-shield-alt"></i>
                    Social Security Number (Encrypted Storage)
                </label>
                <div class="input-wrapper">
                    <input type="password" id="ssn" name="ssn" class="form-input password-input" placeholder="Enter full SSN to update">
                    <button type="button" class="password-toggle" onclick="togglePassword('ssn', this)">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
                {% if ssn %}
                <div class="form-help" style="color: var(--success-color);">
                    <i class="fas fa-check"></i>
                    Current: {{ ssn }}
                </div>
                {% else %}
                <div class="form-help">Your SSN will be encrypted and securely stored</div>
                {% endif %}
            </div>
            
            <div class="btn-group">
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-save"></i>
                    Update Profile
                </button>
                <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">
                    <i class="fas fa-arrow-left"></i>
                    Back to Dashboard
                </a>
            </div>
        </form>
    </div>
    
    <div class="card" style="margin-top: 2rem;">
        <h3 style="margin-bottom: 1rem; color: var(--text-primary);">
            <i class="fas fa-shield-check"></i>
            Security Information
        </h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem;">
            <div style="padding: 1rem; background: var(--background); border-radius: 0.5rem;">
                <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 0.25rem;">Account Status</div>
                <span class="badge badge-success">
                    <i class="fas fa-check"></i>
                    Active & Verified
                </span>
            </div>
            <div style="padding: 1rem; background: var(--background); border-radius: 0.5rem;">
                <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 0.25rem;">Data Encryption</div>
                <span class="badge badge-success">
                    <i class="fas fa-lock"></i>
                    AES-256 Encrypted
                </span>
            </div>
            <div style="padding: 1rem; background: var(--background); border-radius: 0.5rem;">
                <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 0.25rem;">Password Security</div>
                <span class="badge badge-success">
                    <i class="fas fa-key"></i>
                    Bcrypt Hashed
                </span>
            </div>
        </div>
    </div>
</div>
{% endblock %}''',

        'upload.html': '''{% extends "base.html" %}
{% block title %}File Upload - SecureFinTech Pro{% endblock %}
{% block content %}
<div style="max-width: 600px; margin: 0 auto;">
    <div class="card">
        <div style="text-align: center; margin-bottom: 2rem;">
            <h1 style="font-size: 2rem; font-weight: 700; color: var(--text-primary); margin-bottom: 0.5rem;">
                <i class="fas fa-cloud-upload-alt" style="color: var(--primary-color);"></i>
                File Upload
            </h1>
            <p style="color: var(--text-secondary);">Upload documents securely to your account</p>
        </div>
        
        <form method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label for="file" class="form-label">
                    <i class="fas fa-file"></i>
                    Select File
                </label>
                <input type="file" id="file" name="file" class="form-input" accept=".txt,.pdf,.png,.jpg,.jpeg,.gif" required>
                <div class="form-help">
                    <i class="fas fa-info-circle"></i>
                    Allowed types: TXT, PDF, PNG, JPG, JPEG, GIF (max 16MB)
                </div>
            </div>
            
            <div class="btn-group">
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-upload"></i>
                    Upload File
                </button>
                <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">
                    <i class="fas fa-times"></i>
                    Cancel
                </a>
            </div>
        </form>
    </div>
</div>
{% endblock %}''',

        'audit.html': '''{% extends "base.html" %}
{% block title %}Audit Logs - SecureFinTech Pro{% endblock %}
{% block content %}
<div style="margin-bottom: 2rem;">
    <h1 style="font-size: 2rem; font-weight: 700; color: var(--text-primary); margin-bottom: 0.5rem;">
        <i class="fas fa-clipboard-list"></i>
        Audit Logs
    </h1>
    <p style="color: var(--text-secondary);">Track all activities and security events on your account</p>
</div>

<div class="table-container">
    {% if logs %}
    <table class="table">
        <thead>
            <tr>
                <th>Action</th>
                <th>Details</th>
                <th>IP Address</th>
                <th>Timestamp</th>
            </tr>
        </thead>
        <tbody>
            {% for log in logs %}
            <tr>
                <td>
                    <span class="badge badge-{{ 'success' if 'SUCCESS' in log[0] else 'warning' if 'FAILED' in log[0] else 'info' }}">
                        {{ log[0] }}
                    </span>
                </td>
                <td>{{ log[1] }}</td>
                <td style="font-family: monospace; color: var(--text-secondary);">{{ log[2] }}</td>
                <td style="color: var(--text-secondary);">{{ log[3] }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="empty-state">
        <i class="fas fa-clipboard"></i>
        <h3>No audit logs found</h3>
        <p>Activity logs will appear here as you use the application</p>
    </div>
    {% endif %}
</div>

<div style="margin-top: 2rem;">
    <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">
        <i class="fas fa-arrow-left"></i>
        Back to Dashboard
    </a>
</div>
{% endblock %}''',

        'error.html': '''{% extends "base.html" %}
{% block title %}Error {{ error_code }} - SecureFinTech Pro{% endblock %}
{% block content %}
<div style="text-align: center; max-width: 500px; margin: 4rem auto;">
    <div style="font-size: 4rem; color: var(--error-color); margin-bottom: 1rem;">
        <i class="fas fa-exclamation-triangle"></i>
    </div>
    <h1 style="font-size: 3rem; font-weight: 700; color: var(--text-primary); margin-bottom: 1rem;">
        Error {{ error_code }}
    </h1>
    <p style="font-size: 1.25rem; color: var(--text-secondary); margin-bottom: 2rem;">
        {{ error_message }}
    </p>
    <a href="{{ url_for('dashboard') if session.user_id else url_for('login') }}" class="btn btn-primary">
        <i class="fas fa-home"></i>
        Go Home
    </a>
</div>
{% endblock %}'''
    }
    
    # Write templates with UTF-8 encoding to fix Unicode error
    for filename, content in templates.items():
        with open(f'templates/{filename}', 'w', encoding='utf-8') as f:
            f.write(content)
    
    print("SecureFinTech Application Setup Complete!")
    print("Run with: python app.py")
    print("Access at: http://localhost:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
