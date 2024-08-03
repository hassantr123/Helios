from flask import Flask, request, redirect, url_for, render_template, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
from flask_migrate import Migrate
import requests
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from flask_cors import CORS
import smtplib
import random
import ssl
from email.message import EmailMessage


# Load environment variables from .env file
load_dotenv()
verification_codes = {}

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv('SECRET_KEY')  # Required for session management and flashing messages

# Configure PostgreSQL database connection
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)  # Make it nullable

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'User already exists'}), 400

    new_user = User(email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.json  # Get JSON data from request
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        send_verification_code(email)
        user_name = email.split('@')[0]
        return jsonify({'message': 'Login successful'}), 200

    return jsonify({'error': 'Invalid credentials'}), 400


@app.route('/google/login', methods=['GET'])
def login_with_google():
    # Redirect user to Google's OAuth 2.0 authorization server
    authorization_url = 'https://accounts.google.com/o/oauth2/auth'
    redirect_uri = url_for('callback', _external=True)  # Ensure this matches the registered URI
    response_type = 'code'
    client_id = os.getenv('GOOGLE_CLIENT_ID')
    scope = 'openid email'
    state = 'state_parameter'
    auth_url = (f"{authorization_url}?response_type={response_type}&client_id={client_id}&"
                f"redirect_uri={redirect_uri}&scope={scope}&state={state}")

    return redirect(auth_url)

@app.route('/google/login/callback')
def callback():
    # Exchange authorization code for access token and ID token
    code = request.args.get('code')
    if not code:
        return jsonify({'error': 'Authorization code is required'}), 400

    token_url = 'https://oauth2.googleapis.com/token'
    client_id = os.getenv('GOOGLE_CLIENT_ID')
    client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
    redirect_uri = url_for('callback', _external=True)  # Ensure this matches the registered URI
    grant_type = 'authorization_code'
    
    # Prepare token request
    response = requests.post(token_url, data={
        'code': code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': grant_type
    })

    # Get the ID token from the response
    token_data = response.json()
    id_token = token_data.get('id_token')

    if not id_token:
        return jsonify({'error': 'ID token is required'}), 400

    try:
        # Verify the ID token
        id_info = google_id_token.verify_oauth2_token(id_token, google_requests.Request(), client_id)
        email = id_info.get('email')

        # Check if the user exists
        user = User.query.filter_by(email=email).first()

        if not user:
            # Create user with null password_hash
            user = User(email=email)
            db.session.add(user)
            db.session.commit()

        # Log in the user and return a success response
        flash('Login successful')
        return redirect(url_for('index'))

    except ValueError:
        # Invalid token
        return jsonify({'error': 'Invalid token'}), 400



def send_verification_code(email):
    code = random.randint(1000, 9999)
    verification_codes[email] = code

    email_sender = os.getenv('EMAIL_USER')
    email_pass = os.getenv('EMAIL_PASSWORD')  # This should be your app password

    subject = 'Your Verification Code'
    body = f"Your verification code is {code}"

    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, email_pass)
            smtp.sendmail(email_sender, email, em.as_string())
        print("Verification code sent successfully!")
    except Exception as e:
        print(f"Error sending verification code: {e}")

@app.route('/verify', methods=['POST'])
def verify():
    try:
        # Ensure that you receive and parse JSON data correctly
        data = request.json  # Get JSON data from request
        email = data.get('email')
        code = data.get('code')
        code=int(code)
        # Check if the code matches
        if int(verification_codes.get(email)) == code:
            del verification_codes[email]  # Remove the code after verification
            return jsonify({'message': 'Verification successful'}), 200
        
        if not email or not code:
            print(f"Received email: {email}")
            print(f"Received code: {code}")

            return jsonify({'error': 'Email and code are required'}), 400

        
        else:
            return jsonify({'error': 'Invalid verification code'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
