import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'portfolio_secret_2026')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///portfolio_v1.db").replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- MODELS ---
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

# --- REFRESH ADMIN (Fixes "Invalid Credentials") ---
with app.app_context():
    db.create_all()
    admin_email = 'admin@test.gmail.com'
    existing_admin = User.query.filter_by(email=admin_email).first()
    if existing_admin:
        db.session.delete(existing_admin) # Clear old record
        db.session.commit()
    
    new_admin = User(
        full_name="Admin", 
        email=admin_email, 
        password=generate_password_hash('razi123', method='pbkdf2:sha256')
    )
    db.session.add(new_admin)
    db.session.commit()

# --- ROUTES ---

@app.route('/')
def index():
    projects = Project.query.order_by(Project.date_added.desc()).all()
    return render_template('index.html', products=projects)

@app.route('/admin')
@login_required
def admin_panel():
    if current_user.email != 'admin@test.gmail.com': return "Access Denied", 403
    projects = Project.query.all()
    return render_template('admin.html', products=projects)

# FIXED: Route name must be 'add-product' to match your HTML
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('admin_panel') if user.email == 'admin@test.gmail.com' else 'index')
        flash("Invalid Credentials")
    return render_template('login.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
