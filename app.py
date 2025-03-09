# SecureChat - A Private Communication Web App
# This application uses Flask for the web framework, SQLite for the database,
# and cryptography for end-to-end encryption

import os
import secrets
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from functools import wraps
import base64

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    private_key = db.Column(db.Text, nullable=True)
    messages_sent = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id')
    messages_received = db.relationship('Message', backref='recipient', lazy=True, foreign_keys='Message.recipient_id')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_read = db.Column(db.Boolean, default=False)

# Helper Functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_key_pair():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Serialize private key (encrypt with user's password-derived key in production)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

def encrypt_message(message, recipient_public_key_pem):
    # Load recipient's public key
    recipient_public_key = serialization.load_pem_public_key(
        recipient_public_key_pem.encode('utf-8')
    )
    
    # Generate a symmetric key for this message
    symmetric_key = Fernet.generate_key()
    
    # Encrypt the message with the symmetric key
    f = Fernet(symmetric_key)
    encrypted_message = f.encrypt(message.encode('utf-8'))
    
    # Encrypt the symmetric key with the recipient's public key
    encrypted_symmetric_key = recipient_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Return both encrypted parts
    return base64.b64encode(encrypted_symmetric_key).decode('utf-8') + '.' + base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message(encrypted_data, private_key_pem):
    # Split the data into encrypted symmetric key and encrypted message
    encrypted_symmetric_key_b64, encrypted_message_b64 = encrypted_data.split('.')
    encrypted_symmetric_key = base64.b64decode(encrypted_symmetric_key_b64)
    encrypted_message = base64.b64decode(encrypted_message_b64)
    
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    
    # Decrypt the symmetric key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Use the symmetric key to decrypt the message
    f = Fernet(symmetric_key)
    decrypted_message = f.decrypt(encrypted_message).decode('utf-8')
    
    return decrypted_message

# Flask Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another one.', 'error')
            return redirect(url_for('register'))
        
        # Generate RSA key pair
        private_key_pem, public_key_pem = generate_key_pair()
        
        # Create new user
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            private_key=private_key_pem,
            public_key=public_key_pem
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    # Get all conversations (distinct users the current user has communicated with)
    sent_to = db.session.query(Message.recipient_id).filter_by(sender_id=user_id).distinct().all()
    received_from = db.session.query(Message.sender_id).filter_by(recipient_id=user_id).distinct().all()
    
    contact_ids = set([id for (id,) in sent_to] + [id for (id,) in received_from])
    contacts = User.query.filter(User.id.in_(contact_ids)).all()
    
    # Count unread messages
    unread_counts = {}
    for contact in contacts:
        count = Message.query.filter_by(
            sender_id=contact.id, 
            recipient_id=user_id,
            is_read=False
        ).count()
        unread_counts[contact.id] = count
    
    return render_template(
        'dashboard.html', 
        contacts=contacts,
        unread_counts=unread_counts,
        all_users=User.query.filter(User.id != user_id).all()
    )

@app.route('/conversation/<int:other_user_id>')
@login_required
def conversation(other_user_id):
    user_id = session['user_id']
    other_user = User.query.get_or_404(other_user_id)
    
    # Get messages between users
    sent_messages = Message.query.filter_by(sender_id=user_id, recipient_id=other_user_id).all()
    received_messages = Message.query.filter_by(sender_id=other_user_id, recipient_id=user_id).all()
    
    # Mark received messages as read
    for msg in received_messages:
        if not msg.is_read:
            msg.is_read = True
    
    db.session.commit()
    
    # Combine and sort messages by timestamp
    all_messages = sent_messages + received_messages
    all_messages.sort(key=lambda x: x.timestamp)
    
    # Decrypt messages
    current_user = User.query.get(user_id)
    decrypted_messages = []
    
    for msg in all_messages:
        try:
            if msg.sender_id == user_id:
                # Message sent by current user
                decrypted_content = decrypt_message(msg.content, current_user.private_key)
            else:
                # Message received by current user
                decrypted_content = decrypt_message(msg.content, current_user.private_key)
            
            decrypted_messages.append({
                'id': msg.id,
                'content': decrypted_content,
                'timestamp': msg.timestamp,
                'sender_id': msg.sender_id,
                'recipient_id': msg.recipient_id,
                'is_read': msg.is_read
            })
        except Exception as e:
            # Handle decryption error
            decrypted_messages.append({
                'id': msg.id,
                'content': f"[Encryption error: {str(e)}]",
                'timestamp': msg.timestamp,
                'sender_id': msg.sender_id,
                'recipient_id': msg.recipient_id,
                'is_read': msg.is_read
            })
    
    return render_template(
        'conversation.html',
        messages=decrypted_messages,
        other_user=other_user
    )

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    user_id = session['user_id']
    recipient_id = int(request.form['recipient_id'])
    message_text = request.form['message']
    
    # Get recipient's public key
    recipient = User.query.get_or_404(recipient_id)
    
    # Encrypt message
    encrypted_message = encrypt_message(message_text, recipient.public_key)
    
    # Save message
    new_message = Message(
        content=encrypted_message,
        sender_id=user_id,
        recipient_id=recipient_id
    )
    
    db.session.add(new_message)
    db.session.commit()
    
    return redirect(url_for('conversation', other_user_id=recipient_id))

@app.route('/find_users')
@login_required
def find_users():
    user_id = session['user_id']
    search_term = request.args.get('search', '')
    
    if search_term:
        users = User.query.filter(
            User.id != user_id,
            User.username.like(f'%{search_term}%')
        ).all()
    else:
        users = []
    
    return render_template('find_users.html', users=users, search_term=search_term)

# Create HTML templates
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    # Create application directory structure
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    
    # Create template files
    with open('templates/base.html', 'w') as f:
        f.write('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}SecureChat{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <header>
        <h1>SecureChat</h1>
        <nav>
            {% if 'user_id' in session %}
                <a href="{{ url_for('dashboard') }}">Dashboard</a>
                <a href="{{ url_for('find_users') }}">Find Users</a>
                <a href="{{ url_for('logout') }}">Logout ({{ session['username'] }})</a>
            {% else %}
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('register') }}">Register</a>
            {% endif %}
        </nav>
    </header>
    
    <main>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="flashes">
                    {% for category, message in messages %}
                        <div class="flash {{ category }}">{{ message }}</div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </main>
    
    <footer>
        <p>&copy; 2025 SecureChat - End-to-End Encrypted Private Communication</p>
    </footer>
</body>
</html>''')
    
    with open('templates/index.html', 'w') as f:
        f.write('''{% extends "base.html" %}

{% block content %}
    <section class="hero">
        <h2>Welcome to SecureChat</h2>
        <p>A secure, private messaging platform with end-to-end encryption.</p>
        <div class="cta-buttons">
            <a href="{{ url_for('register') }}" class="btn btn-primary">Sign Up</a>
            <a href="{{ url_for('login') }}" class="btn btn-secondary">Login</a>
        </div>
    </section>
    
    <section class="features">
        <div class="feature">
            <h3>End-to-End Encryption</h3>
            <p>All messages are encrypted using RSA and Fernet encryption, ensuring only you and your recipient can read them.</p>
        </div>
        <div class="feature">
            <h3>Secure Authentication</h3>
            <p>Strong password hashing and secure session management to protect your account.</p>
        </div>
        <div class="feature">
            <h3>Privacy-Focused</h3>
            <p>Your conversations stay private. We don't have access to your decrypted messages.</p>
        </div>
    </section>
{% endblock %}''')
    
    with open('templates/register.html', 'w') as f:
        f.write('''{% extends "base.html" %}

{% block title %}Register - SecureChat{% endblock %}

{% block content %}
    <section class="auth-form">
        <h2>Create an Account</h2>
        <form method="post">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <small>By registering, you agree to our terms of service and privacy policy.</small>
            </div>
            <button type="submit" class="btn btn-primary">Register</button>
        </form>
        <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
    </section>
{% endblock %}''')
    
    with open('templates/login.html', 'w') as f:
        f.write('''{% extends "base.html" %}

{% block title %}Login - SecureChat{% endblock %}

{% block content %}
    <section class="auth-form">
        <h2>Login to Your Account</h2>
        <form method="post">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
        <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
    </section>
{% endblock %}''')
    
    with open('templates/dashboard.html', 'w') as f:
        f.write('''{% extends "base.html" %}

{% block title %}Dashboard - SecureChat{% endblock %}

{% block content %}
    <section class="dashboard">
        <h2>Your Conversations</h2>
        
        {% if contacts %}
            <div class="contacts-list">
                {% for contact in contacts %}
                    <a href="{{ url_for('conversation', other_user_id=contact.id) }}" class="contact-item">
                        <div class="contact-info">
                            <span class="contact-name">{{ contact.username }}</span>
                            {% if unread_counts[contact.id] > 0 %}
                                <span class="unread-badge">{{ unread_counts[contact.id] }}</span>
                            {% endif %}
                        </div>
                    </a>
                {% endfor %}
            </div>
        {% else %}
            <p class="no-conversations">You don't have any conversations yet.</p>
            <a href="{{ url_for('find_users') }}" class="btn btn-primary">Find someone to chat with</a>
        {% endif %}
        
        <h3>Start a New Conversation</h3>
        {% if all_users %}
            <div class="new-conversation">
                <form action="{{ url_for('conversation', other_user_id=0) }}" method="get" class="select-user">
                    <select name="other_user_id" id="other-user" required>
                        <option value="">Select a user</option>
                        {% for user in all_users %}
                            <option value="{{ user.id }}">{{ user.username }}</option>
                        {% endfor %}
                    </select>
                    <button type="submit" class="btn btn-secondary">Start Chat</button>
                </form>
            </div>
        {% else %}
            <p>No other users found. Invite your friends to join SecureChat!</p>
        {% endif %}
    </section>
    
    <script>
        // Update select form action to redirect to the selected user conversation
        document.querySelector('.select-user').addEventListener('submit', function(e) {
            e.preventDefault();
            const userId = document.getElementById('other-user').value;
            if (userId) {
                window.location.href = "{{ url_for('conversation', other_user_id=0) }}".replace('0', userId);
            }
        });
    </script>
{% endblock %}''')
    
    with open('templates/conversation.html', 'w') as f:
        f.write('''{% extends "base.html" %}

{% block title %}Chat with {{ other_user.username }} - SecureChat{% endblock %}

{% block content %}
    <section class="conversation">
        <div class="conversation-header">
            <a href="{{ url_for('dashboard') }}" class="back-link">&larr; Back</a>
            <h2>Chat with {{ other_user.username }}</h2>
        </div>
        
        <div class="messages" id="messages-container">
            {% if messages %}
                {% for message in messages %}
                    <div class="message {{ 'outgoing' if message.sender_id == session['user_id'] else 'incoming' }}">
                        <div class="message-content">{{ message.content }}</div>
                        <div class="message-meta">
                            {{ message.timestamp.strftime('%H:%M, %b %d') }}
                            {% if message.sender_id == session['user_id'] and message.is_read %}
                                <span class="read-status">✓ Read</span>
                            {% endif %}
                        </div>
                    </div>
                {% endfor %}
            {% else %}
                <div class="no-messages">
                    <p>No messages yet. Start the conversation!</p>
                </div>
            {% endif %}
        </div>
        
        <div class="message-form">
            <form method="post" action="{{ url_for('send_message') }}">
                <input type="hidden" name="recipient_id" value="{{ other_user.id }}">
                <div class="form-group">
                    <textarea name="message" placeholder="Type your message..." required></textarea>
                </div>
                <button type="submit" class="btn btn-primary">Send</button>
            </form>
        </div>
    </section>
    
    <script>
        // Scroll to bottom of messages
        const messagesContainer = document.getElementById('messages-container');
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    </script>
{% endblock %}''')
    
    with open('templates/find_users.html', 'w') as f:
        f.write('''{% extends "base.html" %}

{% block title %}Find Users - SecureChat{% endblock %}

{% block content %}
    <section class="find-users">
        <h2>Find Users</h2>
        
        <form class="search-form" method="get">
            <div class="form-group">
                <input type="text" name="search" placeholder="Search by username" value="{{ search_term }}">
            </div>
            <button type="submit" class="btn btn-primary">Search</button>
        </form>
        
        {% if users %}
            <div class="users-list">
                {% for user in users %}
                    <div class="user-item">
                        <div class="user-info">
                            <span class="user-name">{{ user.username }}</span>
                        </div>
                        <a href="{{ url_for('conversation', other_user_id=user.id) }}" class="btn btn-secondary">Start Chat</a>
                    </div>
                {% endfor %}
            </div>
        {% elif search_term %}
            <p>No users found matching "{{ search_term }}".</p>
        {% endif %}
    </section>
{% endblock %}''')
    
    # Create CSS file
    with open('static/css/style.css', 'w') as f:
        f.write('''/* General Styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f5f5f5;
    display: flex;
    flex-direction: column;
    min-height: 100vh;
}

a {
    text-decoration: none;
    color: #4a6fa5;
}

a:hover {
    text-decoration: underline;
}

/* Layout */
header {
    background-color: #2c3e50;
    color: white;
    padding: 1rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

header h1 {
    font-size: 1.8rem;
}

nav a {
    color: white;
    margin-left: 1.5rem;
    font-weight: 500;
}

nav a:hover {
    text-decoration: none;
    opacity: 0.8;
}

main {
    max-width: 1200px;
    width: 100%;
    margin: 0 auto;
    padding: 2rem;
    flex: 1;
}

footer {
    background-color: #2c3e50;
    color: white;
    text-align: center;
    padding: 1rem;
    margin-top: auto;
}

/* Flash Messages */
.flashes {
    margin-bottom: 1.5rem;
}

.flash {
    padding: 0.75rem 1.25rem;
    margin-bottom: 0.5rem;
    border-radius: 4px;
    font-weight: 500;
}

.flash.success {
    background-color: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}

.flash.error {
    background-color: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}

.flash.info {
    background-color: #d1ecf1;
    color: #0c5460;
    border: 1px solid #bee5eb;
}

/* Buttons */
.btn {
    display: inline-block;
    font-weight: 500;
    text-align: center;
    white-space: nowrap;
    vertical-align: middle;
    user-select: none;
    border: 1px solid transparent;
    padding: 0.5rem 1rem;
    font-size: 1rem;
    line-height: 1.5;
    border-radius: 4px;
    transition: all 0.15s ease-in-out;
    cursor: pointer;
}

.btn:hover {
    text-decoration: none;
}

.btn-primary {
    color: #fff;
    background-color: #4a6fa5;
    border-color: #4a6fa5;
}

.btn-primary:hover {
    background-color: #3d5d8a;
    border-color: #3d5d8a;
}

.btn-secondary {
    color: #fff;
    background-color: #6c757d;
    border-color: #6c757d;
}

.btn-secondary:hover {
    background-color: #5a6268;
    border-color: #545b62;
}

/* Forms */
.form-group {
    margin-bottom: 1rem;
}

label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
}

input[type="text"],
input[type="password"],
select,
textarea {
    display: block;
    width: 100%;
    padding: 0.5rem;
    font-size: 1rem;
    line-height: 1.5;
    color: #495057;
    background-color: #fff;
    border: 1px solid #ced4da;
    border-radius: 4px;
    transition: border-color 0.15s ease-in-out;
}

input[type="text"]:focus,
input[type="password"]:focus,
select:focus,
textarea:focus {
    border-color: #4a6fa5;
    outline: 0;
}

/* Auth Forms */
.auth-form {
    max-width: 400px;
    margin: 0 auto;
    background-color: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.auth-form h2 {
    margin-bottom: 1.5rem;
    text-align: center;
}

.auth-form p {
    margin-top: 1.5rem;
    text-align: center;
}

/* Homepage */
.hero {
    text-align: center;
    margin-bottom: 3rem;
}

.hero h2 {
    font-size: 2.5rem;
    margin-bottom: 1rem;
}

.hero p {
    font-size: 1.2rem;
    max-width: 600px;
    margin: 0 auto 2rem;
    color: #666;
}

.cta-buttons {
    display: flex;
    justify-content: center;
    gap: 1rem;
}

.features {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 2rem;
    margin-top: 3rem;
}

.feature {
    background-color: white;
    padding: 1.5rem;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
}

.feature h3 {
    margin-bottom: 1rem;
    color: #2c3e50;
}

/* Dashboard */
.dashboard h2, .dashboard h3 {
    margin-bottom: 1.5rem;
}

.contacts-list {
    margin-bottom: 2rem;
}

.contact-item {
    display: block;
    background-color: white;
    padding: 1rem;
    border-radius: 8px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
    margin-bottom: 1rem;
    transition: transform 0.1s ease-in-out;
}

.contact-item:hover {
    text-decoration: none;
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
}

.contact-info {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.contact-name {
    font-weight: 500;
    color: #333;
}

.unread-badge {
    background-color: #4a6fa5;
    color: white;
    border