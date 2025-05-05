from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FloatField
from wtforms.validators import DataRequired, Length, EqualTo
import matplotlib.pyplot as plt, base64, datetime
from io import BytesIO
from sqlalchemy import text

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Lovely%4022august@localhost/shop'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class Shop(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_id = db.Column(db.String(50), unique=True, nullable=False)
    shop_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200))
    phone = db.Column(db.String(20))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    shop_id = db.Column(db.String(50), db.ForeignKey('shop.shop_id'), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    email = StringField('Email', validators=[DataRequired()])
    shop_id = StringField('Shop ID', validators=[DataRequired(), Length(min=4, max=50)])
    shop_name = StringField('Shop Name', validators=[DataRequired(), Length(min=2, max=100)])
    address = StringField('Address')
    phone = StringField('Phone Number')
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register Shop')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CustomerForm(FlaskForm):
    name = StringField('Customer Name', validators=[DataRequired()])
    phone = IntegerField('Phone Number', validators=[DataRequired()])
    cost = FloatField('Cost', validators=[DataRequired()])
    submit = SubmitField('Add Customer')

class ProductForm(FlaskForm):
    product_name = StringField('Product Name', validators=[DataRequired(), Length(max=100)])
    product_cost = FloatField('Product Cost', validators=[DataRequired()])
    submit = SubmitField('Add Product')

class WorkerForm(FlaskForm):
    name = StringField('Worker Name', validators=[DataRequired(), Length(max=100)])
    job = StringField('Job Position', validators=[DataRequired(), Length(max=100)])
    age = IntegerField('Age', validators=[DataRequired()])
    salary = FloatField('Salary', validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired(), Length(max=15)])
    submit = SubmitField('Add Worker')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_current_date():
    return datetime.date.today()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        try:
            # Check if user exists
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already exists', 'danger')
                return redirect(url_for('signup'))
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already registered', 'danger')
                return redirect(url_for('signup'))
            existing_shop = Shop.query.filter_by(shop_id=form.shop_id.data).first()
            if not existing_shop:
                shop = Shop(
                    shop_id=form.shop_id.data,
                    shop_name=form.shop_name.data,
                    address=form.address.data,
                    phone=form.phone.data
                )
                db.session.add(shop)
                db.session.commit()
            
            user = User(
                username=form.username.data,
                email=form.email.data,
                shop_id=form.shop_id.data
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'danger')
            app.logger.error(f'Signup error: {str(e)}')
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=form.username.data).first()
            if user is None:
                flash('Username not found', 'danger')
                return redirect(url_for('login'))                
            if not user.check_password(form.password.data):
                flash('Incorrect password', 'danger')
                return redirect(url_for('login'))               
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))           
        except Exception as e:
            flash('Login error. Please try again.', 'danger')
            app.logger.error(f'Login error: {str(e)}')   
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    # All queries now filter by the current user's shop_id
    customer_count = db.session.execute(
        text("SELECT COUNT(*) FROM customer_details WHERE shop_id = :shop_id"),
        {'shop_id': current_user.shop_id}
    ).fetchone()[0]
    
    product_count = db.session.execute(
        text("SELECT COUNT(*) FROM product_details WHERE shop_id = :shop_id"),
        {'shop_id': current_user.shop_id}
    ).fetchone()[0]
    
    worker_count = db.session.execute(
        text("SELECT COUNT(*) FROM worker_details WHERE shop_id = :shop_id"),
        {'shop_id': current_user.shop_id}
    ).fetchone()[0]
    
    recent_customers = db.session.execute(
        text("SELECT * FROM customer_details WHERE shop_id = :shop_id ORDER BY date DESC LIMIT 5"),
        {'shop_id': current_user.shop_id}
    ).fetchall()
    
    return render_template('dashboard.html', 
                         user=current_user,
                         customer_count=customer_count,
                         product_count=product_count,
                         worker_count=worker_count,
                         recent_customers=recent_customers)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/customers', methods=['GET', 'POST'])
@login_required
def manage_customers():
    form = CustomerForm()
    if form.validate_on_submit():
        try:
            db.session.execute(text(
                "INSERT INTO customer_details (phone, name, cost, date, shop_id) "
                "VALUES (:phone, :name, :cost, :date, :shop_id)"),
                {
                    'phone': form.phone.data,
                    'name': form.name.data,
                    'cost': form.cost.data,
                    'date': get_current_date(),
                    'shop_id': current_user.shop_id
                }
            )
            db.session.commit()
            flash('Customer added successfully!', 'success')
            return redirect(url_for('manage_customers'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding customer: {str(e)}', 'danger')
    
    customers = db.session.execute(
        text("SELECT * FROM customer_details WHERE shop_id = :shop_id ORDER BY date"),
        {'shop_id': current_user.shop_id}
    ).fetchall()
    
    return render_template('customers.html', form=form, customers=customers)

@app.route('/customer/<int:phone>')
@login_required
def view_customer(phone):
    customer = db.session.execute(
        text("SELECT * FROM customer_details WHERE phone = :phone AND shop_id = :shop_id"),
        {'phone': phone, 'shop_id': current_user.shop_id}
    ).fetchone()
    
    if not customer:
        flash('Customer not found', 'danger')
        return redirect(url_for('manage_customers'))
    
    total_debt = db.session.execute(
        text("SELECT SUM(cost) FROM customer_details WHERE phone = :phone AND shop_id = :shop_id"),
        {'phone': phone, 'shop_id': current_user.shop_id}
    ).fetchone()[0]
    
    return render_template('view_customer.html', customer=customer, total_debt=total_debt)

@app.route('/products', methods=['GET', 'POST'])
@login_required
def manage_products():
    form = ProductForm()
    if form.validate_on_submit():
        try:
            db.session.execute(text(
                "INSERT INTO product_details (product_name, product_cost, shop_id) "
                "VALUES (:product_name, :product_cost, :shop_id)"),
                {
                    'product_name': form.product_name.data,
                    'product_cost': form.product_cost.data,
                    'shop_id': current_user.shop_id
                }
            )
            db.session.commit()
            flash('Product added successfully!', 'success')
            return redirect(url_for('manage_products'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding product: {str(e)}', 'danger')
    
    products = db.session.execute(
        text("SELECT * FROM product_details WHERE shop_id = :shop_id"),
        {'shop_id': current_user.shop_id}
    ).fetchall()
    
    return render_template('products.html', form=form, products=products)

@app.route('/product/<int:product_id>')
@login_required
def view_product(product_id):
    product = db.session.execute(
        text("SELECT * FROM product_details WHERE product_id = :product_id AND shop_id = :shop_id"),
        {'product_id': product_id, 'shop_id': current_user.shop_id}
    ).fetchone()
    
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('manage_products'))
    
    return render_template('view_product.html', product=product)

@app.route('/workers', methods=['GET', 'POST'])
@login_required
def manage_workers():
    form = WorkerForm()
    if form.validate_on_submit():
        try:
            db.session.execute(text(
                "INSERT INTO worker_details (name, job, age, salary, phone_number, shop_id) "
                "VALUES (:name, :job, :age, :salary, :phone_number, :shop_id)"),
                {
                    'name': form.name.data,
                    'job': form.job.data,
                    'age': form.age.data,
                    'salary': form.salary.data,
                    'phone_number': form.phone_number.data,
                    'shop_id': current_user.shop_id
                }
           )
            db.session.commit()
            flash('Worker added successfully!', 'success')
            return redirect(url_for('manage_workers'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding worker: {str(e)}', 'danger')  
    
    workers = db.session.execute(
        text("SELECT * FROM worker_details WHERE shop_id = :shop_id"),
        {'shop_id': current_user.shop_id}
    ).fetchall()
    
    return render_template('workers.html', form=form, workers=workers)

@app.route('/worker/<int:worker_id>')
@login_required
def view_worker(worker_id):
    worker = db.session.execute(
        text("""
            SELECT worker_id, name, job, age, salary, phone_number, 
                   created_at as date_added 
            FROM worker_details 
            WHERE worker_id = :worker_id AND shop_id = :shop_id
        """),
        {'worker_id': worker_id, 'shop_id': current_user.shop_id}
    ).fetchone()

    if not worker:
        flash('Worker not found or you don\'t have permission', 'danger')
        return redirect(url_for('manage_workers'))

    return render_template('view_worker.html', worker=worker)

@app.route('/worker/delete/<int:worker_id>', methods=['POST'])
@login_required
def delete_worker(worker_id):
    try:
        db.session.execute(
            text("DELETE FROM worker_details WHERE worker_id = :worker_id AND shop_id = :shop_id"),
            {'worker_id': worker_id, 'shop_id': current_user.shop_id}
        )
        db.session.commit()
        flash('Worker deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting worker: {str(e)}', 'danger')
    return redirect(url_for('manage_workers'))

@app.route('/product/delete/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    try:
        db.session.execute(
            text("DELETE FROM product_details WHERE product_id = :product_id AND shop_id = :shop_id"),
            {'product_id': product_id, 'shop_id': current_user.shop_id}
        )
        db.session.commit()
        flash('Product deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting product: {str(e)}', 'danger')
    return redirect(url_for('manage_products'))
@app.route('/customer/delete/<int:phone>', methods=['POST'])
@login_required
def delete_customer(phone):
    try:
        db.session.execute(
            text("DELETE FROM customer_details WHERE phone = :phone AND shop_id = :shop_id"),
            {'phone': phone, 'shop_id': current_user.shop_id}
        )
        db.session.commit()
        flash('Customer and all related records deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting customer: {str(e)}', 'danger')
        app.logger.error(f'Error deleting customer: {str(e)}')
    return redirect(url_for('manage_customers'))
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)