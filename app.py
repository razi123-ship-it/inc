import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text 

app = Flask(__name__)

# --- 1. CONFIGURATION ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'portfolio_secret_2026')
database_url = os.environ.get("DATABASE_URL", "sqlite:///portfolio_v1.db")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
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
    image_2 = db.Column(db.String(500)) 
    description = db.Column(db.Text)
    date_added = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- DATABASE INITIALIZATION & ADMIN CREATION ---
with app.app_context():
    db.create_all()
    # Check if your specific admin account exists, if not, create it
    admin_check = User.query.filter_by(email='admin@test.gmail.com').first()
    if not admin_check:
        hashed_pw = generate_password_hash('razi123', method='pbkdf2:sha256')
        new_admin = User(
            full_name="Admin", 
            email='admin@test.gmail.com', 
            password=hashed_pw
        )
        db.session.add(new_admin)
        db.session.commit()

# --- 3. MAIN PORTFOLIO ROUTES ---
@app.route('/')
def index():
    projects = Project.query.order_by(Project.date_added.desc()).all()
    return render_template('index.html', products=projects)

@app.route('/project/<int:id>')
def project_detail(id):
    project = db.session.get(Project, id)
    if not project:
        flash("Project not found")
        return redirect(url_for('index'))
    return render_template('product_detail.html', product=project)

# --- 4. ADMIN PANEL ---
@app.route('/admin')
@login_required
def admin_panel():
    if current_user.email != 'admin@test.gmail.com': 
        return "Access Denied", 403
    
    projects = Project.query.order_by(Project.date_added.desc()).all()
    return render_template('admin.html', products=projects)

@app.route('/admin/add-project', methods=['POST'])
@login_required
def add_product():
    if current_user.email != 'admin@test.gmail.com': return "Denied", 403
    
    name = request.form.get('name')
    image = request.form.get('image')
    image_2 = request.form.get('image_2')
    category = request.form.get('category')
    description = request.form.get('description')
    
    new_project = Project(
        name=name, 
        image=image, 
        image_2=image_2,
        category=category,
        description=description
    )
    db.session.add(new_project)
    db.session.commit()
    flash("Project Published Successfully!")
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete-project/<int:id>')
@login_required
def delete_product(id):
    if current_user.email != 'admin@test.gmail.com': return "Denied", 403
    project = db.session.get(Project, id)
    if project:
        db.session.delete(project)
        db.session.commit()
        flash("Project Removed")
    return redirect(url_for('admin_panel'))

# --- 5. AUTHENTICATION ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        password = request.form.get('password')
        
        if User.query.filter_by(email=email).first():
            flash("Email already registered.")
            return redirect(url_for('login'))
            
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(full_name=full_name, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            # This is the fix: go to admin panel if the email matches yours
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
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
