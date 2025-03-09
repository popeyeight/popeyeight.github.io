from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Registration Successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            flash('Login Successful!', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/chat", methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        recipient_username = request.form.get('recipient')
        content = request.form.get('message')
        recipient = User.query.filter_by(username=recipient_username).first()
        if recipient:
            message = Message(sender_id=current_user.id, recipient_id=recipient.id, content=content)
            db.session.add(message)
            db.session.commit()
            flash('Message sent!', 'success')
        else:
            flash('Recipient not found.', 'danger')
    messages = Message.query.filter((Message.sender_id==current_user.id) | (Message.recipient_id==current_user.id)).all()
    return render_template('chat.html', messages=messages)

if __name__ == "__main__":
    app.run(debug=True)