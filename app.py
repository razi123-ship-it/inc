import os
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text 

app = Flask(__name__)

# --- 1. CONFIGURATION ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'evia_final_secret_2026')
database_url = os.environ.get("DATABASE_URL", "sqlite:///evia_final_v18.db")
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
    orders = db.relationship('Order', backref='customer', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(500))
    image_2 = db.Column(db.String(500)) 
    description = db.Column(db.Text)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_details = db.Column(db.Text)
    total_price = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(50), default="Placed")
    address = db.Column(db.Text)
    whatsapp = db.Column(db.String(20))
    date_ordered = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- DATABASE INITIALIZATION ---
with app.app_context():
    db.create_all()
    try:
        db.session.execute(text('SELECT image_2 FROM product LIMIT 1'))
    except:
        db.session.execute(text('ALTER TABLE product ADD COLUMN image_2 VARCHAR(500)'))
        db.session.commit()

# --- 3. MAIN ROUTES ---
# Replace your current @app.route('/') with this:
@app.route('/')
def index():
    query = request.args.get('q') # Gets the text from the search box
    if query:
        # This filters the database for names that contain your search word
        products = Product.query.filter(Product.name.ilike(f'%{query}%')).all()
    else:
        # If no search, show everything
        products = Product.query.all()
        
    cart = session.get('cart', [])
    if not isinstance(cart, list): cart = []
    return render_template('index.html', products=products, cart_count=len(cart))

@app.route('/product/<int:id>')
def product_detail(id):
    product = db.session.get(Product, id)
    if not product:
        flash("Product not found")
        return redirect(url_for('index'))
    return render_template('product_detail.html', product=product)

# --- 4. CART LOGIC ---
@app.route('/add-to-cart/<int:id>')
def add_to_cart(id):
    if 'cart' not in session or not isinstance(session['cart'], list):
        session['cart'] = []
    cart = list(session['cart'])
    cart.append(id)
    session['cart'] = cart
    session.modified = True 
    flash("Added to bag")
    return redirect(url_for('index'))

@app.route('/buy-now/<int:id>')
def buy_now(id):
    session['cart'] = [id]
    session.modified = True
    return redirect(url_for('cart_view'))

@app.route('/cart')
def cart_view():
    cart_ids = session.get('cart', [])
    items = [db.session.get(Product, p_id) for p_id in cart_ids if db.session.get(Product, p_id)]
    total = sum(i.price for i in items)
    return render_template('cart.html', items=items, total=total)

@app.route('/remove-from-cart/<int:id>')
def remove_from_cart(id):
    if 'cart' in session:
        cart = list(session['cart'])
        if id in cart:
            cart.remove(id)
            session['cart'] = cart
            session.modified = True
    return redirect(url_for('cart_view'))

# --- 5. CHECKOUT ---
@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_ids = session.get('cart', [])
    if not cart_ids: 
        return redirect(url_for('index'))
    
    user_address = request.form.get('address')
    user_whatsapp = request.form.get('whatsapp')
    
    if not user_address or not user_whatsapp:
        flash("Please provide address and WhatsApp number.")
        return redirect(url_for('cart_view'))
    
    items = [db.session.get(Product, p_id) for p_id in cart_ids if db.session.get(Product, p_id)]
    details = ", ".join([p.name for p in items])
    total = sum(p.price for p in items)
    
    try:
        new_order = Order(
            product_details=details, 
            total_price=total, 
            user_id=current_user.id,
            address=user_address,
            whatsapp=user_whatsapp
        )
        db.session.add(new_order)
        db.session.commit()
        session.pop('cart', None)
        flash("Order Placed Successfully!")
        return redirect(url_for('profile'))
    except Exception as e:
        db.session.rollback()
        flash("Error placing order. Please try again.")
        return redirect(url_for('cart_view'))

# --- 6. USER PROFILE & ORDER ACTIONS (CANCEL/RETURN) ---
@app.route('/profile')
@login_required
def profile():
    try:
        orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.date_ordered.desc()).all()
        return render_template('profile.html', orders=orders)
    except Exception:
        return "Error loading profile", 500

@app.route('/cancel-order/<int:id>')
@login_required
def cancel_order(id):
    order = db.session.get(Order, id)
    if order and order.user_id == current_user.id:
        if order.status == "Placed":
            order.status = "Cancelled"
            db.session.commit()
            flash("Order has been cancelled.")
        else:
            flash("Order cannot be cancelled at this stage.")
    return redirect(url_for('profile'))

@app.route('/return-order/<int:id>')
@login_required
def return_order(id):
    order = db.session.get(Order, id)
    if order and order.user_id == current_user.id:
        if order.status == "Delivered":
            order.status = "Return Requested"
            db.session.commit()
            flash("Return request submitted.")
        else:
            flash("Return not available for this status.")
    return redirect(url_for('profile'))

# --- 7. ADMIN ---
@app.route('/admin')
@login_required
def admin_panel():
    if current_user.email != 'admin@test.gmail.com': return "Denied", 403
    orders = Order.query.order_by(Order.date_ordered.desc()).all()
    products = Product.query.all() 
    return render_template('admin.html', orders=orders, products=products)

@app.route('/admin/add-product', methods=['POST'])
@login_required
def add_product():
    if current_user.email != 'admin@test.gmail.com': return "Denied", 403
    name = request.form.get('name')
    price = request.form.get('price')
    image = request.form.get('image')
    image_2 = request.form.get('image_2')
    description = request.form.get('description')
    
    new_p = Product(
        name=name, price=int(price), 
        image=image, image_2=image_2,
        description=description
    )
    db.session.add(new_p)
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/update-status/<int:id>/<string:new_status>')
@login_required
def update_status(id, new_status):
    if current_user.email != 'admin@test.gmail.com': return "Denied", 403
    order = db.session.get(Order, id)
    if order:
        order.status = new_status
        db.session.commit()
        flash(f"Order updated to {new_status}")
    return redirect(url_for('admin_panel'))

# --- 8. AUTHENTICATION ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        password = request.form.get('password')
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
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
            return redirect(url_for('index'))
        flash("Invalid Credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/reset-system', methods=['POST'])
@login_required
def reset_system():
    if current_user.email != 'admin@test.gmail.com':
        return "Denied", 403
    db.session.query(Order).delete()
    User.query.filter(User.email != 'admin@test.gmail.com').delete()
    db.session.commit()
    flash("System Reset Successful")
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)

