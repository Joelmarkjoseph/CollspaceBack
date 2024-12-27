from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import datetime
from functools import wraps
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from flask_mail import Mail, Message
import random
import os
from authlib.jose import jwt

app = Flask(__name__)
CORS(app)

# Database configuration
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

# Initialize SQLAlchemy and Flask-Migrate
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Define the Student model
class Student(db.Model):
    __tablename__ = 'student'
    rollno = db.Column(db.String(15), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    section = db.Column(db.String(50), nullable=False)
    mobileno = db.Column(db.BigInteger, nullable=False)
    college = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(1000), nullable=False)
    mailid = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<Student {self.name}>"

# Function to generate JWT token
def generate_token(student):
    payload = {
        'sub': student.rollno,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }

    header = {"alg": "HS256"}  # Algorithm for token encoding
    token = jwt.encode(header, payload, secret_key)  # Authlib's JWT encoding
    return token.decode("utf-8")  # Ensure it returns a string if needed


# JWT Token Verification Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs, user_id=data['sub'])
    return decorated

@app.route('/')
def index():
    return jsonify({"message": "Welcome to Flask with Render!"})

@app.route('/dashboard', methods=['GET'])
@token_required
def dashdata(user_id):
    students = Student.query.filter(Student.rollno == user_id).all()
    return jsonify([{
        "rollno": student.rollno,
        "name": student.name,
        "year": student.year,
        "branch": student.branch,
        "section": student.section,
        "mobileno": student.mobileno,
        "college": student.college
    } for student in students])

@app.route('/students', methods=['GET'])
def get_students():
    """
    Endpoint to get the list of all students.
    Returns a JSON array of all students in the database.
    """
    students = Student.query.all()
    return jsonify([{
        "rollno": student.rollno,
        "name": student.name,
        "year": student.year,
        "branch": student.branch,
        "section": student.section,
        "mobileno": student.mobileno,
        "college": student.college,
        "mailid": student.mailid
    } for student in students]), 200


@app.route('/add_student', methods=['POST'])
def add_student():
    data = request.get_json()

    # Ensure OTP is verified
    if data['mailid'] not in verified_emails:
        return jsonify({"error": "OTP verification is required before adding a student"}), 403

    # Check if student already exists
    if Student.query.filter_by(rollno=data['rollno']).first():
        return jsonify({'error': 'Student with this roll number already exists'}), 400

    # Hash the password
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')

    # Add student to the database
    new_student = Student(
        rollno=data['rollno'],
        name=data['name'],
        year=data['year'],
        branch=data['branch'],
        section=data['section'],
        mobileno=data['mobileno'],
        college=data['college'],
        mailid=data['mailid'],
        password=hashed_password
    )

    db.session.add(new_student)
    db.session.commit()

    # Remove from verified list after successful registration
    verified_emails.remove(data['mailid'])

    return jsonify({"message": "Student added successfully!"}), 201

# Route to login (generates JWT token)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    student = Student.query.filter_by(rollno=data['rollno']).first()

    if student and check_password_hash(student.password, data['password']):
        token = generate_token(student)
        return jsonify({"message": "Login successful!", "token": token}), 200

    return jsonify({"error": "Invalid roll number or password"}), 401

# Protected route to test JWT authentication
@app.route('/protected', methods=['GET'])
@token_required
def protected(user_id):
    return jsonify({"message": f"Access granted for user {user_id}!"}), 200


# Configure Flask-Mail

app.config['MAIL_DEFAULT_SENDER'] = 'joelmarkjoseph2004@gmail.com'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

# Store the OTP for each user (in a real application, use a more secure solution)
otp_dict = {}

@app.route('/sendotp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('mailid')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
    otp_dict[email] = otp

    # Send OTP via email
    msg = Message("Your OTP for Signup", recipients=[email])
    msg.body = f"Your OTP is: {otp}"

    try:
        mail.send(msg)
        return jsonify({"message": "OTP sent successfully to your email!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


verified_emails = set()

@app.route('/verifyotp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('mailid')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required"}), 400

    # Check if the OTP is correct
    if otp_dict.get(email) == int(otp):
        del otp_dict[email]  # Remove the OTP after verification
        verified_emails.add(email)  # Mark email as verified
        return jsonify({"message": "OTP verified successfully!"}), 200
    else:
        return jsonify({"error": "Invalid OTP"}), 400


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
