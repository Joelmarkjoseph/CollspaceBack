from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import firestore
import datetime
import os
from authlib.jose import jwt
from functools import wraps
import random
from flask_mail import Mail, Message

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Firestore initialization
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.getenv('GOOGLE_APPLICATION_CREDENTIALS', '/etc/secrets/firebasecred')
db = firestore.Client()

# Secret key configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'joelseckey')

# Mail configuration
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'joelmarkjoseph2004@gmail.com')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

# JWT token generation
def generate_token(user_id):
    payload = {
        'sub': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    header = {"alg": "HS256"}
    secret_key = app.config['SECRET_KEY']
    token = jwt.encode(header, payload, secret_key)
    return token.decode("utf-8")

# JWT token verification
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').split("Bearer ")[-1]
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs, user_id=data['sub'])
    return decorated


# Unified JWT token verification decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Extract the token from the Authorization header
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split("Bearer ")[-1] if "Bearer " in auth_header else None

        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            # Decode the token
            data = jwt.decode(token, app.config['SECRET_KEY'])
            kwargs['user_id'] = data['sub']  # Pass user_id to the wrapped function
        except jwt.ExpiredTokenError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated

# Simplify /dashboard endpoint
@app.route('/dashboard', methods=['GET'])
@token_required
def get_dashboard(user_id):
    try:
        # Query Firestore for user data
        query = db.collection('students').where('rollno', '==', user_id)
        student_docs = query.stream()
        student_data = [doc.to_dict() for doc in student_docs]

        if not student_data:
            return jsonify({"message": "No data found for this user."}), 404

        # Send back student data
        return jsonify(student_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/')
def index():
    return jsonify({"message": "Welcome to the Firestore-based Backend Server!"})

@app.route('/students', methods=['GET'])
def get_students():
    students_ref = db.collection('students')
    students = [doc.to_dict() for doc in students_ref.stream()]
    return jsonify(students), 200

@app.route('/add_student', methods=['POST'])
def add_student():
    data = request.get_json()
    student_ref = db.collection('students').document(data['rollno'])
    if student_ref.get().exists:
        return jsonify({"error": "Student already exists"}), 400

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    student_data = {
        'rollno': data['rollno'],
        'name': data['name'],
        'year': data['year'],
        'branch': data['branch'],
        'section': data['section'],
        'mobileno': data['mobileno'],
        'college': data['college'],
        'mailid': data['mailid'],
        'password': hashed_password
    }
    student_ref.set(student_data)
    return jsonify({"message": "Student added successfully!"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    rollno = data.get('rollno')
    password = data.get('password')

    student_ref = db.collection('students').document(rollno)
    student = student_ref.get()
    if not student.exists or not check_password_hash(student.to_dict()['password'], password):
        return jsonify({"error": "Invalid roll number or password"}), 401

    token = generate_token(rollno)
    return jsonify({"message": "Login successful!", "token": token}), 200

@app.route('/sendotp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('mailid')
    if not email:
        return jsonify({"error": "Email is required"}), 400

    otp = random.randint(100000, 999999)
    db.collection('otps').document(email).set({'otp': otp, 'timestamp': datetime.datetime.utcnow()})
    msg = Message("Your OTP", recipients=[email])
    msg.body = f"Your OTP is: {otp}"
    try:
        mail.send(msg)
        return jsonify({"message": "OTP sent successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/verifyotp', methods=['POST'])
def verify_otp():
   
    data = request.get_json()
    email = data.get('mailid')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required"}), 400

    try:
        # Retrieve OTP details from Firestore
        otp_ref = db.collection('otps').document(email)
        otp_doc = otp_ref.get()

        if not otp_doc.exists:
            return jsonify({"error": "OTP not found. Please request a new OTP."}), 404

        otp_data = otp_doc.to_dict()
        stored_otp = otp_data.get('otp')
        timestamp = otp_data.get('timestamp')

        # Check if the OTP is valid
        if str(otp) != str(stored_otp):
            return jsonify({"error": "Invalid OTP. Please try again."}), 401

        # OTP verified successfully; remove it from Firestore
        otp_ref.delete()
        return jsonify({"message": "OTP verified successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Start the Flask server
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Use dynamic port for Render
    app.run(host='0.0.0.0', port=port)
