from flask import Blueprint, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token
from datetime import timedelta
from Models.models import db, User
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from . import authoperations as authops


bcrypt = Bcrypt()
auth_bp = Blueprint('auth', __name__)

limiter = Limiter(get_remote_address, default_limits=["100 per minute"])

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("100 per minute")
def register():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid input'}), 400
        
        # Extract and validate input
        fname = data.get('fname', '').strip()
        lname = data.get('lname', '').strip()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()

        # Validate email
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            return jsonify({'data': [], 'statusCode': 200, 'message': 'Invalid email format'})

        # Validate password strength
        if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
            return jsonify({'data': [], 'statusCode': 200, 'message': 'Password must be at least 8 characters long and include both letters and numbers'})

        # Check if user exists
        if User.query.filter((User.username == username) | (User.email == email)).first():
            return jsonify({'data': [], 'statusCode': 200,'message': 'Username or email already exists'})

        # Hash the password securely
        password_hash = authops.hash_password(password)

        # Create new user instance
        new_user = User(fname=fname, lname=lname, username=username, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        logging.info(f"New user registered: {username} ({email})")

        return jsonify({'data': [], 'statusCode': 201, 'message': 'User registered successfully.'}), 201

    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/login', methods=['POST'])
@limiter.limit("100 per minute")
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid input'}), 400

        identifier = data.get('email') or data.get('username')
        password = data.get('password')

        if not identifier or not password:
            return jsonify({'error': 'Missing email/username or password'}), 400
        # Fetch user by email or username
        user = User.query.filter((User.email == identifier) | (User.username == identifier)).first()

        # Check if user exists
        if not user:
            return jsonify({'data': [], 'statusCode': 200, 'message': 'Invalid credentials'})

        # Verify password using Argon2
        if not authops.verify_password(user.password_hash, password):
            logging.warning(f"Failed login attempt for user {user.username}")
            return jsonify({'data': [], 'statusCode': 401, 'message': 'Invalid credentials'}), 401

        # Create JWT access token (24-hour expiry)
        access_token = create_access_token(identity=user.id, expires_delta=timedelta(days=1))

        logging.info(f"User {user.username} logged in successfully")

        return jsonify({'data': {'access_token': access_token}, 'statusCode': 200, 'message': 'logged in successfully'})
    
    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
