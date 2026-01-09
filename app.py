import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- 1. CONFIGURATION ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'portfolio_secret_2026')

# Handling your razi.db environment variable
database_url = os.environ.get("DATABASE_URL", "sqlite:///portfolio_v1.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
# This part fixes it if you only typed 'razi.db' in Render's settings
elif not database_url.startswith("sqlite://") and not database_url.startswith("postgresql://"):
    database_url = f"sqlite:///{database_url}"

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- 2. MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), default="Design") 
    image = db.Column(db.String(500))
    description = db.Column(db.Text)
    date_added = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- 3. DATABASE INIT & ADMIN RESET ---
with app.app_context():
    db.create_all()
    # This ensures your password 'razi123' always works after a fresh deploy
    admin_email = 'admin@test.gmail.com'
    admin_user = User.query.filter_by(email=admin_email).first()
    if admin_user:
        db.session.delete(admin_user)
        db.session.commit()
    
    new_admin = User(
        full_name="Admin", 
        email=admin_email, 
        password=generate_password_hash('razi123', method='pbkdf2:sha256')
    )
    db.session.add(new_admin)
    db.session.commit()

# --- 4. ROUTES ---

@app.route('/')
def index():
    projects = Project.query.order_by(Project.date_added.desc()).all()
    return render_template('index.html', products=projects)

@app.route('/admin')
@login_required
def admin_panel():
    if current_user.email != 'admin@test.gmail.com':
        return "Access Denied", 403
    projects = Project.query.order_by(Project.date_added.desc()).all()
    return render_template('admin.html', products=projects)

# Matches <form action="/admin/add-product">
@app.route('/admin/add-product', methods=['POST'])
@login_required
def add_product():
    if current_user.email != 'admin@test.gmail.com': return "Denied", 403
    
    new_project = Project(
        name=request.form.get('name'),
        image=request.form.get('image'),
        category=request.form.get('category'),
        description=request.form.get('description')
    )
    db.session.add(new_project)
    db.session.commit()
    flash("Project Published!")
    return redirect(url_for('admin_panel'))

# Matches <a href="/admin/delete-product/{{id}}">
@app.route('/admin/delete-product/<int:id>')
@login_required
def delete_product(id):
    if current_user.email != 'admin@test.gmail.com': return "Denied", 403
    project = db.session.get(Project, id)
    if project:
        db.session.delete(project)
        db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            if user.email == 'admin@test.gmail.com':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('index'))
        flash("Invalid Credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Fix for Render: must listen on 0.0.0.0 and the PORT env var
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
