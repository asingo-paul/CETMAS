import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import bcrypt
from werkzeug.utils import secure_filename
from datetime import timedelta
from flask_mail import Mail, Message
from dotenv import load_dotenv
from collections import defaultdict, Counter

# Load .env variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

# MySQL Configuration
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST')
app.config['MYSQL_PORT'] = int(os.environ.get('MYSQL_PORT', 3306))
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB')

mysql = MySQL(app)

#Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

mail = Mail(app)

#admin logins

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

#Session
app.permanent_session_lifetime = timedelta(days=7)

#File Upload
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.before_request
def make_session_permanent():
    session.permanent = True

#Inject Cart Count
@app.context_processor
def inject_cart_count():
    cart = session.get('cart', {})
    cart_count = sum(item['quantity'] for item in cart.values())
    return dict(cart_count=cart_count)

#USER ROUTES
@app.route('/')
def home():
    return render_template('users/index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        cursor.close()

        if not user:
            flash('Email does not exist! Please Register.', 'danger')
            return redirect(url_for('login'))

        if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            # Save only the ID in session
            session['user_id'] = user['id']
            flash('Login successful!', 'success')
            return redirect(url_for('products'))
        else:
            flash('Incorrect password.', 'danger')
            return redirect(url_for('login'))

    return render_template('users/index.html')


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
        county = request.form['county']
        town = request.form['town']

        # Validations
        if not phone.isdigit():
            flash('Phone number must contain digits only.', 'danger')
            return redirect(url_for('register'))

        if len(phone) != 9:
            flash('Phone number must be exactly 9 digits.', 'danger')
            return redirect(url_for('register'))

        if password != confirm:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('register'))

        cursor = mysql.connection.cursor()

        # 🔹 Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            flash('⚠️ Email already registered! Please use another one.', 'danger')
            return redirect(url_for('register'))

        # Hash password
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Save to DB
        cursor.execute('''
            INSERT INTO users (first_name, second_name, email, password_hash, phone, county, town) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        ''', (first_name, second_name, email, hashed.decode('utf-8'), full_phone, county, town))
        mysql.connection.commit()
        cursor.close()

        return render_template('users/register_success.html', email=email)

    return render_template('users/register.html')




@app.route('/products')
def products():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products")
    items = cursor.fetchall()
    return render_template('users/products.html', items=items)

@app.route('/cart')
def cart():
    cart = session.get('cart', {})
    total = sum(item['price'] * item['quantity'] for item in cart.values())
    return render_template('users/cart.html', cart=cart, total=total)

@app.route('/add-to-cart/<int:product_id>')
def add_to_cart(product_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash("Product not found.", "danger")
        return redirect(url_for('products'))

    cart = session.get('cart', {})
    pid = str(product_id)

    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'id': product['id'],
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart
    flash("Added to cart!", "success")
    return redirect(url_for('products'))



@app.route('/order-all', methods=['POST', 'GET'])
def order_all():
    if 'user_id' not in session:
        flash("You must be logged in to place an order.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    email = user['email']

    cart = session.get('cart', {})

    if not cart:
        flash("Your cart is empty.", "warning")
        return redirect(url_for('cart'))

    for item in cart.values():
        cursor.execute("""
            INSERT INTO orders (email, product_id, quantity)
            VALUES (%s, %s, %s)
        """, (email, item['id'], item['quantity']))
        cursor.execute("""
            UPDATE products SET stock = stock - %s
            WHERE id = %s
        """, (item['quantity'], item['id']))

    mysql.connection.commit()
    cursor.close()

    # Clear cart after ordering
    session['cart'] = {}
    flash("Your order for all items has been placed successfully!", "success")
    return redirect(url_for('products'))



@app.route('/order-now/<int:product_id>', methods=['GET'])
def order_now(product_id):
    if 'user_id' not in session:
        flash("You must be logged in to place an order.", "danger")
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Fetch user email
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    email = user['email']

    # Fetch product info
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()

    if not product or product['stock'] <= 0:
        flash("This product is out of stock.", "warning")
        return redirect(url_for('products'))

    # Insert order
    cursor.execute("""
        INSERT INTO orders (email, product_id, quantity)
        VALUES (%s, %s, %s)
    """, (email, product_id, 1))  # quantity = 1 for instant order
    cursor.execute("""
        UPDATE products SET stock = stock - 1
        WHERE id = %s
    """, (product_id,))
    mysql.connection.commit()
    cursor.close()

    flash("Order placed successfully!", "success")
    return redirect(url_for('products'))



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



@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        msg = Message(f"New Message from {name}",
                      sender=email,
                      recipients=['paulasingo32@gmail.com'])

        msg.body = f"From: {name} <{email}>\n\nMessage:\n{message}"

        try:
            mail.send(msg)
            flash('Your message has been sent successfully!', 'success')
        except Exception:
            flash('There was an error sending your message.', 'danger')

        return redirect(url_for('contact'))

    return render_template('users/contact.html')

@app.route('/profile')
def profile():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to view your profile.", "warning")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT id, first_name, second_name, email, phone, county, town 
        FROM users WHERE id = %s
    """, (user_id,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('login'))

    return render_template('users/profile.html', user=user)



@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        flash('Reset instructions have been sent!', 'info')
        return redirect(url_for('login'))
    return render_template('users/forgot_password.html')


@app.route('/search_products', methods=['GET'])
def search_products():
    query = request.args.get('q', '').strip()
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)


    if query:
        sql = """
            SELECT * FROM products
            WHERE name LIKE %s OR description LIKE %s
            ORDER BY name ASC
        """
        cursor.execute(sql, (f"%{query}%", f"%{query}%"))
    else:
        cursor.execute("SELECT * FROM products ORDER BY name ASC")

    items = cursor.fetchall()
    cursor.close()

    return render_template('users/products.html', items=items, query=query)



@app.route('/buy/<int:product_id>')
def buy_now(product_id):
    # logic for checkout or immediate purchase
    return f'Buy Now for product {product_id}'

@app.route('/logout')
def logout():
    session.pop('user', None)  # Remove user from session
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('home'))

#admin routes

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['is_admin'] = True
            return redirect(url_for('admin_inventory'))
        else:
            flash("Invalid admin credentials!", "danger")
    return render_template('admin/admin_login.html')




#ADMIN ROUTES
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            flash("Admin access required!", "danger")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/admin/add-product', methods=['GET', 'POST'])
@admin_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        stock = request.form['stock']
        image = request.files['image']

        if image.filename == '':
            flash('No image selected.', 'warning')
            return redirect(url_for('add_product'))

        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        cursor = mysql.connection.cursor()
        cursor.execute("""
            INSERT INTO products (name, description, price, image, stock) 
            VALUES (%s, %s, %s, %s, %s)
        """, (name, description, price, filename, stock))
        mysql.connection.commit()

        flash('Product added successfully!', 'success')
        return redirect(url_for('admin_inventory'))

    return render_template('admin/admin_add_product.html')

@app.route('/admin/inventory')
@admin_required
def admin_inventory():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    return render_template('admin/admin_inventory.html', products=products)

@app.route('/admin/edit/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        stock = request.form['stock']
        description = request.form['description']
        cursor.execute("""
            UPDATE products SET name=%s, description=%s, price=%s, stock=%s WHERE id=%s
        """, (name, description, price, stock, product_id))
        mysql.connection.commit()
        flash("Product updated", "success")
        return redirect(url_for('admin_inventory'))
    else:
        cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
        product = cursor.fetchone()
        return render_template('admin/admin_edit_product.html', product=product)

@app.route('/admin/delete/<int:product_id>', methods=['GET', 'POST'])
@admin_required
def delete_product(product_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()

    if request.method == 'POST':
        cursor.execute("DELETE FROM products WHERE id = %s", (product_id,))
        mysql.connection.commit()
        flash(f"Product '{product['name']}' deleted.", "success")
        return redirect(url_for('admin_inventory'))

    return render_template('admin/admin_delete_product.html', product=product)



@app.route('/admin/orders')
@admin_required
def admin_orders():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT 
            o.id,
            u.id AS user_id,
            u.first_name,
            u.second_name,
            u.county,
            u.town,
            p.name AS product,
            p.price,              -- get price of product
            o.quantity,
            o.created_at,
            o.confirmed
        FROM orders o
        JOIN users u ON o.email = u.email
        JOIN products p ON o.product_id = p.id
        ORDER BY o.created_at DESC
    """)
    orders = cursor.fetchall()

    grouped_orders = defaultdict(list)
    for order in orders:
        grouped_orders[order['user_id']].append(order)

    final_orders = {}
    for user_id, user_orders in grouped_orders.items():
        product_counter = Counter()
        total_price = 0

        for o in user_orders:
            product_counter[o['product']] += o['quantity']
            total_price += o['quantity'] * o['price']  # calc total

        product_list = [f"{prod} ({qty})" for prod, qty in product_counter.items()]
        base_order = user_orders[0]

        final_orders[user_id] = {
            "user": f"{base_order['first_name']} {base_order['second_name']}",
            "county": base_order['county'],
            "town": base_order['town'],
            "products": ", ".join(product_list),
            "date": base_order['created_at'],
            "confirmed": base_order['confirmed'],
            "id": base_order['id'],
            "total": total_price,   # add total
        }

    return render_template('admin/admin_orders.html', grouped_orders=final_orders)




@app.route('/admin/suppliers')
@admin_required
def suppliers():
    suppliers = [
        {
            'id': 1,
            'name': 'asingo paul',
            'company': 'Global Supplies Ltd',
            'email': 'asingo@global.com',
            'phone': '0712345678',
            'products': [
                {
                    'name': 'Ink Cartridge',
                    'description': 'High quality black ink for Epson printers.',
                    'image': 'ink.jpg',  # image must exist in static/uploads
                    'stock': 50,
                    'price': 1200.00
                },
                {
                    'name': 'Color Toner',
                    'description': 'Magenta toner for HP LaserJet.',
                    'image': 'toner.jpg',
                    'stock': 30,
                    'price': 3500.00
                },

                {
                    'name': 'Color Toner',
                    'description': 'Magenta toner for HP LaserJet.',
                    'image': 'toner.jpg',
                    'stock': 30,
                    'price': 3500.00
                },

                {
                    'name': 'Color Toner',
                    'description': 'Magenta toner for HP LaserJet.',
                    'image': 'toner.jpg',
                    'stock': 30,
                    'price': 3500.00
                },

                {
                    'name': 'Color Toner',
                    'description': 'Magenta toner for HP LaserJet.',
                    'image': 'toner.jpg',
                    'stock': 30,
                    'price': 3500.00
                },

                {
                    'name': 'Color Toner',
                    'description': 'Magenta toner for HP LaserJet.',
                    'image': 'toner.jpg',
                    'stock': 30,
                    'price': 3500.00
                }
            ]
        },
        {
            'id': 2,
            'name': 'Reuben Willis',
            'company': 'OfficeMart Kenya',
            'email': 'wils@officemart.co.ke',
            'phone': '0798765432',
            'products': [
                {
                    'name': 'A4 Paper Pack',
                    'description': '500 sheets of high-quality A4 paper.',
                    'image': '',
                    'stock': 200,
                    'price': 650.00
                }
            ]
        },


         {
            'id': 2,
            'name': 'Reuben Willis',
            'company': 'OfficeMart Kenya',
            'email': 'wils@officemart.co.ke',
            'phone': '0798765432',
            'products': [
                {
                    'name': 'A4 Paper Pack',
                    'description': '500 sheets of high-quality A4 paper.',
                    'image': 'alter tb2.png',
                    'stock': 200,
                    'price': 650.00
                },
                 {
                    'name': 'Color Toner',
                    'description': 'Magenta toner for HP LaserJet.',
                    'image': 'toner.jpg',
                    'stock': 30,
                    'price': 3500.00
                },
                 {
                    'name': 'Color Toner',
                    'description': 'Magenta toner for HP LaserJet.',
                    'image': 'toner.jpg',
                    'stock': 30,
                    'price': 3500.00
                }
            ]
        }
    ]

    return render_template("admin/admin_suppliers.html", suppliers=suppliers)



@app.route('/admin/logout')
def logout_admin():
    session.pop('is_admin', None)   # clear admin session
    flash("You have been logged out!", "info")
    return redirect(url_for('home'))


@app.route('/admin/orders/confirm/<int:order_id>', methods=['POST'])
def confirm_order(order_id):
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE orders SET confirmed=1 WHERE id=%s", (order_id,))
    mysql.connection.commit()
    return redirect(url_for('admin_orders'))

    

@app.route('/admin/orders/delete/<int:user_id>', methods=['POST'])
def delete_order(user_id):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM orders WHERE email = (SELECT email FROM users WHERE id=%s)", (user_id,))
    mysql.connection.commit()
    return redirect(url_for('admin_orders'))







#Run App
if __name__ == '__main__':
    app.run()
