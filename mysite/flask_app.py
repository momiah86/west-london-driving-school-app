from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from flask_migrate import Migrate
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
import os
import csv
import pdfkit
import pandas as pd  # For Excel exports
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

# Initialize Flask-Limiter with simple configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# OAuth Setup
oauth = OAuth(app)
app.config['GOOGLE_CLIENT_ID'] = 'your_google_client_id'
app.config['GOOGLE_CLIENT_SECRET'] = 'your_google_client_secret'

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'}
)

# Define the LoginForm class
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

# Add this form class near your other forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Register')

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_instructor = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Student Model
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    middle_name = db.Column(db.String(100))
    surname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15))
    address = db.Column(db.String(200))
    email = db.Column(db.String(150))
    license_number = db.Column(db.String(50))
    check_code = db.Column(db.String(50))
    disqualifications = db.Column(db.String(500))
    theory_test_status = db.Column(db.String(100))
    theory_test_expiry = db.Column(db.Date)
    practical_test_date = db.Column(db.Date)
    practical_test_center = db.Column(db.String(200))
    notes = db.Column(db.Text)

# Log Model
class LessonLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    lesson_number = db.Column(db.Integer, nullable=False)
    hours_delivered = db.Column(db.Float, nullable=False)
    credit_left = db.Column(db.Float, nullable=False)
    topics_covered = db.Column(db.Text)
    date = db.Column(db.Date, nullable=False)
    notes = db.Column(db.Text)
    student = db.relationship('Student', backref='lesson_logs')

# Message Model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

csrf = CSRFProtect(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

with app.app_context():
    db.create_all()

# Routes
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        remember = form.remember_me.data

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('dashboard')
            
            flash('Successfully logged in!', 'success')
            return redirect(next_page)
        else:
            flash('Invalid email or password.', 'error')
            time.sleep(1)  # Add delay to prevent brute force

    return render_template('login.html', form=form)

@app.route('/login/google')
def google_login():
    # Your Google login logic here
    pass

@app.route('/login/apple')
def apple_login():
    # Your Apple login logic here
    pass

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if user already exists
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered. Please login.', 'error')
            return redirect(url_for('login'))
        
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already taken. Please choose another.', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        user = User(
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            print(f"Registration error: {str(e)}")
            
    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_instructor:
        return render_template('dashboard.html', students=Student.query.all())
    else:
        student = Student.query.filter_by(email=current_user.email).first()
        if not student:
            flash('No student record found for your email.', 'danger')
            return redirect(url_for('logout'))  # Log out the user if no student record exists
        return render_template('student_dashboard.html', logs=student.lesson_logs)

@app.route('/instructor-dashboard')
@login_required
def instructor_dashboard():
    if not current_user.is_instructor:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', students=Student.query.all())

@app.route('/student-dashboard')
@login_required
def student_dashboard():
    # Debugging: Check if the user is authenticated
    print("User authenticated:", current_user.is_authenticated)

    if current_user.is_instructor:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))
    student = Student.query.filter_by(email=current_user.email).first()
    if not student:
        flash('No student record found for your email.', 'danger')
        return redirect(url_for('logout'))  # Log out the user if no student record exists
    return render_template('student_dashboard.html', logs=student.lesson_logs)

@app.route('/add-student', methods=['POST'])
@login_required
def add_student():
    if current_user.is_instructor:
        data = request.form
        if not data.get('first_name') or not data.get('surname') or not data.get('email'):
            flash('First name, surname, and email are required.', 'danger')
            return redirect(url_for('dashboard'))

        student = Student(
            first_name=data['first_name'],
            middle_name=data.get('middle_name'),
            surname=data['surname'],
            phone=data['phone'],
            address=data['address'],
            email=data['email'],
            license_number=data['license_number'],
            check_code=data['check_code'],
            theory_test_status=data['theory_test_status'],
            theory_test_expiry=data.get('theory_test_expiry'),
            practical_test_date=data.get('practical_test_date'),
            practical_test_center=data['practical_test_center'],
            notes=data['notes']
        )
        db.session.add(student)
        db.session.commit()
        flash('Student added successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/export-logs/<file_type>', methods=['GET'])
@login_required
def export_logs(file_type):
    logs = LessonLog.query.all()  # Fetch all logs
    output = []
    for log in logs:
        output.append([
            log.student.first_name + ' ' + log.student.surname,
            log.lesson_number,
            log.hours_delivered,
            log.credit_left,
            log.topics_covered,
            log.date,
            log.notes
        ])

    if file_type == 'csv':
        csv_content = "".join(",".join(map(str, row)) + "\n" for row in output)
        response = Response(csv_content, mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename=logs.csv'
        return response

    elif file_type == 'pdf':
        html_content = render_template('logs_pdf.html', logs=logs)
        pdf = pdfkit.from_string(html_content, False)
        response = Response(pdf, mimetype='application/pdf')
        response.headers['Content-Disposition'] = 'attachment; filename=logs.pdf'
        return response

    elif file_type == 'excel':
        df = pd.DataFrame(output, columns=['Student Name', 'Lesson Number', 'Hours Delivered', 'Credit Left', 'Topics Covered', 'Date', 'Notes'])
        excel_file = df.to_excel(index=False)
        response = Response(excel_file, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response.headers['Content-Disposition'] = 'attachment; filename=logs.xlsx'
        return response

    flash('Invalid export type', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    if request.method == 'POST':
        recipient_id = request.form['recipient_id']
        message_content = request.form['message']
        message = Message(sender_id=current_user.id, recipient_id=recipient_id, message=message_content)
        db.session.add(message)
        db.session.commit()
        flash('Message sent successfully', 'success')
    users = User.query.all()
    received_messages = current_user.received_messages
    return render_template('messages.html', users=users, messages=received_messages)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Add these to your app config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Update this
app.config['MAIL_PASSWORD'] = 'your-app-password'     # Update this
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'  # Update this

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Add these new routes
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate token
            token = serializer.dumps(user.email, salt='password-reset-salt')
            
            # Create password reset link
            reset_url = url_for('reset_password_token', 
                              token=token, 
                              _external=True)
            
            # Send email
            msg = Message('Password Reset Request',
                        recipients=[user.email])
            msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email.
'''
            mail.send(msg)
            
            flash('Password reset instructions sent to your email.', 'info')
            return redirect(url_for('login'))
        
        flash('Email address not found.', 'error')
        return redirect(url_for('reset_password'))
    
    return render_template('reset_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        email = serializer.loads(token, 
                               salt='password-reset-salt', 
                               max_age=3600)  # Token expires in 1 hour
    except:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('reset_password'))
    
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        if user:
            password = request.form.get('password')
            user.set_password(password)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password_token.html')

if __name__ == "__main__":
    app.run(debug=True, port=5003)