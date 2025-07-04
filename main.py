from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import bcrypt
from werkzeug.utils import secure_filename
import os 
from datetime import timedelta
from flask_mail import Mail, Message
from dotenv import load_dotenv


app = Flask(__name__)

app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# MySQL configuration
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST')
app.config['MYSQL_PORT'] = int(os.environ.get('MYSQL_PORT', 3306))
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB')

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')    # Use an app-specific password

mail = Mail(app)
# Session duration config
app.permanent_session_lifetime = timedelta(days=7)

mysql = MySQL(app)

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.before_request
def make_session_permanent():
    session.permanent = True

# 🔴 Context processor to inject cart_count into all templates
@app.context_processor
def inject_cart_count():
    cart = session.get('cart', {})
    cart_count = sum(item['quantity'] for item in cart.values())
    return dict(cart_count=cart_count)

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            session['user'] = {
                'email': user['email'],
                'first_name': user['first_name'],
                'phone': user['phone']
            }
            flash('Login successful!', 'success')
            return redirect(url_for('products'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        second_name = request.form['second_name']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']
        code = request.form['code']
        phone = request.form['phone']
        full_phone = code + phone

        if password != confirm:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())    

        cursor = mysql.connection.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (first_name, second_name, email, password_hash, phone) 
                VALUES (%s, %s, %s, %s, %s)''',
                (first_name, second_name, email, hashed.decode('utf-8'), full_phone)
            )
            mysql.connection.commit()
            flash('Registration successful!', 'success')
        except MySQLdb._exceptions.IntegrityError as e:
            print("DB Error:", e)
            flash('Email already registered!', 'danger')
        return redirect(url_for('home'))
    return render_template('register.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        flash('Reset instructions have been sent!', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')


@app.route('/profile')
def profile():
    user = session.get('user')
    if not user:
        flash("Please log in to view your profile.", "warning")
        return redirect(url_for('login'))
    return render_template('profile.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/update-cart/<int:product_id>/<action>')
def update_cart(product_id, action):
    cart = session.get('cart', {})
    product_id_str = str(product_id)

    if product_id_str in cart:
        if action == 'add':
            cart[product_id_str]['quantity'] += 1
        elif action == 'subtract' and cart[product_id_str]['quantity'] > 1:
            cart[product_id_str]['quantity'] -= 1
        elif action == 'remove':
            del cart[product_id_str]

    session['cart'] = cart
    session.modified = True
    return redirect(url_for('cart'))

@app.route('/add-to-cart/<int:product_id>')
def add_to_cart(product_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash("Product not found.", "danger")
        return redirect(url_for('products'))

    cart = session.get('cart', {})
    product_id_str = str(product_id)

    if product_id_str in cart:
        cart[product_id_str]['quantity'] += 1
    else:
        cart[product_id_str] = {
            'id': product['id'],
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart
    session.modified = True
    flash("Added to cart!", "success")
    return redirect(url_for('products'))

@app.route('/cart')
def cart():
    cart = session.get('cart', {})
    total = sum(item['price'] * item['quantity'] for item in cart.values())
    return render_template('cart.html', cart=cart, total=total)

@app.route('/products')
def products():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products")
    items = cursor.fetchall()
    return render_template('products.html', items=items)

@app.route('/order-now')
def order_now():
    if 'cart' not in session:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('products'))

    user_info = session.get('user')
    if not user_info:
        flash("You must be logged in to place an order.", "danger")
        return redirect(url_for('login'))

    email = user_info['email']
    cart = session['cart']

    cursor = mysql.connection.cursor()
    for item in cart.values():
        cursor.execute("""
            INSERT INTO orders (email, product_id, quantity)
            VALUES (%s, %s, %s)
        """, (email, item['id'], item['quantity']))

        cursor.execute("""
            UPDATE products SET stock = stock - %s
            WHERE id = %s AND stock >= %s
        """, (item['quantity'], item['id'], item['quantity']))

    mysql.connection.commit()
    flash("Order placed successfully! (Simulated)", "success")
    session.pop('cart', None)
    return redirect(url_for('products'))


@app.route('/buy/<int:product_id>')
def buy_now(product_id):
    # logic for checkout or immediate purchase
    return f'Buy Now for product {product_id}'


@app.route('/search')
def search_products():
    query = request.args.get('q', '').lower()

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM products WHERE LOWER(name) LIKE %s OR LOWER(description) LIKE %s", 
                (f"%{query}%", f"%{query}%"))
    filtered_products = cur.fetchall()

    return render_template('products.html', items=filtered_products, cart_count=session.get('cart_count', 0))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Compose email
        msg = Message(f"New Message from {name}",
                      sender=email,
                      recipients=['asingopaul66@gmail.com'])  # Replace with your receiving email

        msg.body = f"From: {name} <{email}>\n\nMessage:\n{message}"

        try:
            mail.send(msg)
            flash('Your message has been sent successfully!', 'success')
        except Exception as e:
            print("Error:", e)
            flash('There was an error sending your message.', 'danger')

        return redirect(url_for('contact'))

    return render_template('contact.html')

@app.route('/supplier')
def supplier():

    return render_template('suppliers.html')



@app.route("/better")
def better():

    return "<h2>hello buddy</h2>"


if __name__ == '__main__':
    app.run(debug=True)
