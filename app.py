from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
import re
import os
from dotenv import load_dotenv
from bson import ObjectId
from werkzeug.utils import secure_filename
import uuid
import logging

from flask_socketio import SocketIO, emit, join_room, leave_room

load_dotenv()

app = Flask(__name__, static_folder="public", template_folder="src/pages")
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))
app.config.update({
    'SESSION_COOKIE_SECURE': False,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'UPLOAD_FOLDER': os.path.abspath(os.path.join(os.path.dirname(__file__), 'uploads')),
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024
})

bcrypt = Bcrypt(app)
CORS(app, supports_credentials=True, resources={
    r"/uploads/*": {"origins": ["http://127.0.0.1:5000", "http://localhost:5000"]},
    r"/api/*": {"origins": ["http://127.0.0.1:5000", "http://localhost:5000"]}
})

socketio = SocketIO(app, cors_allowed_origins=["http://127.0.0.1:5000", "http://localhost:5000"])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    mongo_client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017/SkillSwap"), serverSelectionTimeoutMS=5000)
    mongo_client.server_info()
    db = mongo_client['SkillSwap']
    users_collection = db['Users']
    skills_collection = db['Skills']
    feedback_collection = db['Feedback']
    availability_collection = db['Availability']
    messages_collection = db['Messages']
except Exception as e:
    logger.error(f"Database connection failed: {e}")
    exit(1)

def allowed_file(filename):
    logger.info(f"Checking file: {filename}, extension: {filename.rsplit('.', 1)[1].lower() if '.' in filename else 'None'}")
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

def unique_filename(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return f"{uuid.uuid4().hex}.{ext}"

def validate_user_input(data, required_fields):
    missing = [field for field in required_fields if not data.get(field)]
    return f"Missing fields: {', '.join(missing)}" if missing else None

def validate_password(password):
    return re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password) is not None

@app.route('/')
def home():
    return render_template('homepage_skill_swap.html')

@app.route('/login.html')
def login_page():
    return render_template('login.html')

@app.route('/register.html')
def register_page():
    return render_template('register.html')

@app.route('/dashboard.html')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('dashboard.html')

@app.route('/profile.html')
def profile_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('profile.html')

@app.route('/search.html')
def search_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('search.html')

@app.route('/exchange.html')
def exchange_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('exchange.html')

@app.route('/messages.html')
def messages_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('messages.html')

@app.route('/reviews.html')
def reviews_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('reviews.html')

@app.route('/setting.html')
def setting_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('setting.html')

@app.route('/<path:path>')
def serve_static(path):
    return app.send_static_file(path)

@app.route('/api/register', methods=['POST'])
def register_user():
    try:
        data = request.get_json()
        if error := validate_user_input(data, ['email', 'password', 'full_name', 'location']):
            return jsonify({'error': error}), 400

        if users_collection.find_one({'email': data['email']}):
            return jsonify({'error': 'Email already registered'}), 400

        if not validate_password(data['password']):
            return jsonify({'error': 'Invalid password format'}), 400

        user = {
            'full_name': data['full_name'],
            'email': data['email'],
            'password_hash': bcrypt.generate_password_hash(data['password']).decode('utf-8'),
            'created_at': datetime.utcnow(),
            'profile_picture': '',
            'bio': '',
            'resume': '',
            'skills': [],
            'skill_hours': 0,
            'location': data.get('location', 'Remote')
        }
        result = users_collection.insert_one(user)
        session['user_id'] = str(result.inserted_id)
        logger.info(f"Registered user with ID: {result.inserted_id}")
        return jsonify({
            'message': 'Registration successful',
            'redirect': '/profile.html',
            'user': {'id': str(result.inserted_id), 'full_name': user['full_name'], 'email': user['email']}
        })
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        user = users_collection.find_one({'email': data.get('email')})

        if user and bcrypt.check_password_hash(user['password_hash'], data.get('password', '')):
            session['user_id'] = str(user['_id'])
            logger.info(f"Logged in user with ID: {user['_id']}, Session user_id: {session['user_id']}")
            return jsonify({
                'message': 'Login successful',
                'redirect': '/profile.html',
                'user': {'id': str(user['_id']), 'full_name': user['full_name'], 'email': user['email']}
            })
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    logger.info("User logged out")
    return jsonify({'message': 'Logged out successfully', 'redirect': '/login.html'})

@app.route('/api/profile', methods=['GET'])
def get_profile():
    try:
        if 'user_id' not in session:
            logger.error("Unauthorized access to /api/profile: No user_id in session")
            return jsonify({'error': 'Unauthorized'}), 401

        user_id = session.get('user_id')
        logger.info(f"Fetching profile for user_id: {user_id}")
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            logger.error(f"User not found with user_id: {user_id}")
            return jsonify({'error': 'User not found'}), 404

        skills = list(skills_collection.find({'user_id': user_id}))
        logger.info(f"Profile data fetched for user_id: {user_id}, User: {user}, Skills: {skills}")
        return jsonify({
            'full_name': user['full_name'],
            'email': user['email'],
            'bio': user.get('bio', ''),
            'profile_picture': user.get('profile_picture', ''),
            'resume': user.get('resume', ''),
            'skills': [{
                'skill_id': str(skill['_id']),
                'skill_name': skill['skill_name'],
                'experience_level': skill['experience_level'],
                'skill_type': skill.get('skill_type', 'N/A'),
                'specialties': skill['specialties'],
                'availability': skill['availability'],
                'certifications': skill.get('certifications', ''),
                'description': skill.get('description', ''),
                'portfolio': skill.get('portfolio', '')
            } for skill in skills],
            'skill_hours': user.get('skill_hours', 0),
            'location': user.get('location', 'Remote')
        })
    except Exception as e:
        logger.error(f"Profile fetch error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/update_profile', methods=['POST'])
def update_profile():
    try:
        if 'user_id' not in session:
            logger.error("Unauthorized access to /api/update_profile: No user_id in session")
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        allowed_fields = ['full_name', 'bio', 'location', 'skill_hours']
        update_data = {k: v for k in allowed_fields if (v := data.get(k)) is not None}

        if not update_data:
            return jsonify({'error': 'No valid fields to update'}), 400

        if 'skill_hours' in update_data:
            try:
                update_data['skill_hours'] = int(update_data['skill_hours'])
                if update_data['skill_hours'] < 0:
                    return jsonify({'error': 'Skill hours cannot be negative'}), 400
            except (ValueError, TypeError):
                return jsonify({'error': 'Skill hours must be a valid integer'}), 400

        user_id = session.get('user_id')
        logger.info(f"Updating profile for user_id: {user_id} with {update_data}")
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )
        if result.matched_count == 0:
            logger.error(f"No user found with user_id: {user_id}")
            return jsonify({'error': 'User not found'}), 404

        logger.info(f"Profile updated successfully for user_id: {user_id}")
        return jsonify({'message': 'Profile updated'})
    except Exception as e:
        logger.error(f"Profile update error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload_profile_picture', methods=['POST'])
def upload_profile_picture():
    try:
        logger.info(f"Raw request data: {request.get_data(as_text=True)}")
        logger.info(f"Request files: {request.files}")
        if 'file' not in request.files:
            logger.error(f"No 'file' key in request.files: {request.files}")
            return jsonify({'error': 'No file'}), 400

        file = request.files['file']
        logger.info(f"File object: {file}, filename: {file.filename if file else 'None'}")
        if not file or not allowed_file(file.filename):
            logger.error(f"Invalid file: {file.filename if file else 'None'}, allowed types: {allowed_file}")
            return jsonify({'error': 'Invalid file'}), 400

        filename = unique_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        logger.info(f"File saved to {filepath}")

        relative_path = f'/uploads/{filename}'
        user_id = session.get('user_id')
        logger.info(f"Updating profile_picture for user_id: {user_id} to {relative_path}")
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'profile_picture': relative_path}}
        )
        logger.info(f"Update result: matched {result.matched_count}, modified {result.modified_count}")
        if result.matched_count == 0:
            logger.error(f"No user found with user_id: {user_id}")
            return jsonify({'error': 'User not found'}), 404

        return jsonify({'message': 'Profile picture uploaded', 'path': relative_path})
    except Exception as e:
        logger.error(f"Error uploading profile picture: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload_resume', methods=['POST'])
def upload_resume():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file'}), 400

        file = request.files['file']
        if not file or not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file'}), 400

        filename = unique_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        relative_path = f'/uploads/{filename}'
        result = users_collection.update_one(
            {'_id': ObjectId(session.get('user_id'))},
            {'$set': {'resume': relative_path}}
        )
        logger.info(f"Resume saved at {relative_path}")
        return jsonify({'message': 'Resume updated', 'path': relative_path})
    except Exception as e:
        logger.error(f"Error uploading resume: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        logger.info(f"Attempting to serve file from {full_path}")
        if not os.path.exists(full_path):
            logger.error(f"File not found: {full_path} - Directory contents: {os.listdir(app.config['UPLOAD_FOLDER'])}")
            return jsonify({'error': 'File not found'}), 404
        logger.info(f"File found and serving: {full_path}")
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}")
        return jsonify({'error': 'File not found'}), 404

@app.route('/api/add_skill', methods=['POST'])
def add_skill():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        if error := validate_user_input(data, ['skill_name', 'experience_level', 'skill_type', 'specialties', 'availability']):
            return jsonify({'error': error}), 400

        user_id = session.get('user_id')
        skill = {
            'user_id': user_id,
            'skill_name': data['skill_name'],
            'experience_level': data['experience_level'],
            'skill_type': data['skill_type'],
            'specialties': data['specialties'],
            'availability': data['availability'],
            'certifications': data.get('certifications', ''),
            'description': data.get('description', ''),
            'portfolio': data.get('portfolio', ''),
            'created_at': datetime.utcnow()
        }
        result = skills_collection.insert_one(skill)
        logger.info(f"Skill added for user_id: {user_id}, skill_id: {result.inserted_id}")
        return jsonify({'message': 'Skill added successfully', 'skill_id': str(result.inserted_id)}), 201
    except Exception as e:
        logger.error(f"Error adding skill: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/update_skill/<skill_id>', methods=['PUT'])
def update_skill(skill_id):
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        update_data = {k: v for k in [
            'skill_name', 'experience_level', 'skill_type', 'specialties',
            'availability', 'certifications', 'description', 'portfolio'
        ] if (v := data.get(k)) is not None}

        user_id = session.get('user_id')
        result = skills_collection.update_one(
            {'_id': ObjectId(skill_id), 'user_id': user_id},
            {'$set': update_data}
        )
        if result.modified_count == 0:
            return jsonify({'error': 'Skill not found or not authorized'}), 404

        logger.info(f"Skill updated: {skill_id} for user_id: {user_id}")
        return jsonify({'message': 'Skill updated'})
    except Exception as e:
        logger.error(f"Error updating skill {skill_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete_skill/<skill_id>', methods=['DELETE'])
def delete_skill(skill_id):
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        user_id = session.get('user_id')
        result = skills_collection.delete_one({
            '_id': ObjectId(skill_id),
            'user_id': user_id
        })
        if result.deleted_count == 0:
            return jsonify({'error': 'Skill not found or not authorized'}), 404

        logger.info(f"Skill deleted: {skill_id} for user_id: {user_id}")
        return jsonify({'message': 'Skill deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting skill {skill_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/skill-hours', methods=['POST'])
def update_skill_hours():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        action = data.get('action')
        value = data.get('value', 0)

        user_id = session.get('user_id')
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        current_hours = user.get('skill_hours', 0)
        
        if action == 'add':
            new_hours = current_hours + value
        elif action == 'subtract':
            new_hours = max(0, current_hours - value)
        else:
            return jsonify({'error': 'Invalid action'}), 400

        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'skill_hours': new_hours}}
        )
        return jsonify({'hours': new_hours})
    except Exception as e:
        logger.error(f"Error updating skill hours: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/submit-feedback', methods=['POST'])
def submit_feedback():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        feedback = data.get('feedback', '')

        if not feedback:
            return jsonify({'error': 'Feedback is required'}), 400

        user_id = session.get('user_id')
        feedback_collection.insert_one({
            'user_id': user_id,
            'feedback': feedback,
            'created_at': datetime.utcnow()
        })
        return jsonify({'message': 'Feedback submitted successfully'})
    except Exception as e:
        logger.error(f"Error submitting feedback: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/availability', methods=['GET'])
def get_availability():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        user_id = session.get('user_id')
        availability = list(availability_collection.find({'user_id': user_id}))
        return jsonify([{
            '_id': str(doc['_id']),
            'start_time': doc['start_time'],
            'end_time': doc['end_time'],
            'description': doc.get('description', 'Available')
        } for doc in availability])
    except Exception as e:
        logger.error(f"Error fetching availability: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/add_availability', methods=['POST'])
def add_availability():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        if error := validate_user_input(data, ['start_time', 'end_time']):
            return jsonify({'error': error}), 400

        user_id = session.get('user_id')
        availability = {
            'user_id': user_id,
            'start_time': data['start_time'],
            'end_time': data['end_time'],
            'description': data.get('description', 'Available'),
            'created_at': datetime.utcnow()
        }
        result = availability_collection.insert_one(availability)
        logger.info(f"Availability added for user_id: {user_id}, availability_id: {result.inserted_id}")
        return jsonify({'message': 'Availability added successfully', '_id': str(result.inserted_id)}), 201
    except Exception as e:
        logger.error(f"Error adding availability: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete_availability/<availability_id>', methods=['DELETE'])
def delete_availability(availability_id):
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        user_id = session.get('user_id')
        result = availability_collection.delete_one({
            '_id': ObjectId(availability_id),
            'user_id': user_id
        })
        if result.deleted_count == 0:
            return jsonify({'error': 'Availability not found or not authorized'}), 404

        logger.info(f"Availability deleted: {availability_id} for user_id: {user_id}")
        return jsonify({'message': 'Availability deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting availability {availability_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/search_skills', methods=['POST'])
def search_skills():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        query = data.get('query', '').lower()
        skill_type = data.get('skill_type', 'all')
        experience_levels = data.get('experience_levels', [])
        location = data.get('location', '').lower()

        users = list(users_collection.find())
        matched_users = []

        for user in users:
            user_skills = list(skills_collection.find({'user_id': str(user['_id'])}))
            if not user_skills:
                continue

            matches_query = not query or any(query in skill['skill_name'].lower() for skill in user_skills)
            matches_skill_type = skill_type == 'all' or any(skill.get('skill_type', 'N/A') == skill_type for skill in user_skills)
            matches_experience = not experience_levels or any(skill['experience_level'] in experience_levels for skill in user_skills)
            matches_location = not location or location in user.get('location', 'Remote').lower()

            if matches_query and matches_skill_type and matches_experience and matches_location:
                matched_users.append({
                    'full_name': user['full_name'],
                    'profile_picture': user.get('profile_picture', ''),
                    'skills': [{
                        'skill_id': str(skill['_id']),
                        'skill_name': skill['skill_name'],
                        'experience_level': skill['experience_level'],
                        'skill_type': skill.get('skill_type', 'N/A'),
                        'specialties': skill['specialties'],
                        'availability': skill['availability'],
                        'certifications': skill.get('certifications', ''),
                        'description': skill.get('description', ''),
                        'portfolio': skill.get('portfolio', '')
                    } for skill in user_skills],
                    'skill_hours': user.get('skill_hours', 0),
                    'location': user.get('location', 'Remote')
                })

        logger.info(f"Search completed with query: {query}, skill_type: {skill_type}, experience: {experience_levels}, location: {location}")
        return jsonify({'users': matched_users})
    except Exception as e:
        logger.error(f"Error searching skills: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/messages', methods=['GET'])
def get_messages():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        user_id = session.get('user_id')
        receiver_id = request.args.get('receiver_id')

        if not receiver_id:
            return jsonify({'error': 'Receiver ID is required'}), 400

        messages = list(messages_collection.find({
            '$or': [
                {'sender_id': user_id, 'receiver_id': receiver_id},
                {'sender_id': receiver_id, 'receiver_id': user_id}
            ]
        }).sort('timestamp', 1))

        return jsonify([{
            'sender_id': str(msg['sender_id']),
            'receiver_id': str(msg['receiver_id']),
            'message': msg['message'],
            'timestamp': msg['timestamp'].isoformat()
        } for msg in messages])
    except Exception as e:
        logger.error(f"Error fetching messages: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/send_message', methods=['POST'])
def send_message():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        if error := validate_user_input(data, ['receiver_id', 'message']):
            return jsonify({'error': error}), 400

        sender_id = session.get('user_id')
        receiver_id = data['receiver_id']
        message = data['message']

        message_doc = {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'message': message,
            'timestamp': datetime.utcnow()
        }
        result = messages_collection.insert_one(message_doc)
        logger.info(f"Message sent from {sender_id} to {receiver_id}, message_id: {result.inserted_id}")

        socketio.emit('new_message', {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'message': message,
            'timestamp': message_doc['timestamp'].isoformat()
        }, room=receiver_id)

        return jsonify({'message': 'Message sent successfully'})
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat_list', methods=['GET'])
def get_chat_list():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        user_id = session.get('user_id')
        conversations = list(messages_collection.aggregate([
            {
                '$match': {
                    '$or': [
                        {'sender_id': user_id},
                        {'receiver_id': user_id}
                    ]
                }
            },
            {
                '$sort': {'timestamp': -1}
            },
            {
                '$group': {
                    '_id': {
                        '$cond': [
                            {'$eq': ['$sender_id', user_id]},
                            '$receiver_id',
                            '$sender_id'
                        ]
                    },
                    'last_message': {'$first': '$message'},
                    'timestamp': {'$first': '$timestamp'}
                }
            }
        ]))

        chat_list = []
        for conv in conversations:
            user = users_collection.find_one({'_id': ObjectId(conv['_id'])})
            if user:
                chat_list.append({
                    'user_id': str(conv['_id']),
                    'user_name': user['full_name'],
                    'profile_picture': user.get('profile_picture', ''),
                    'last_message': conv['last_message']
                })

        return jsonify(chat_list)
    except Exception as e:
        logger.error(f"Error fetching chat list: {e}")
        return jsonify({'error': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    if user_id:
        join_room(user_id)
        logger.info(f"User {user_id} connected to SocketIO")

@socketio.on('disconnect')
def handle_disconnect():
    user_id = session.get('user_id')
    if user_id:
        leave_room(user_id)
        logger.info(f"User {user_id} disconnected from SocketIO")

@socketio.on('join_room')
def on_join(data):
    user_id = session.get('user_id')
    if user_id and data.get('room'):
        join_room(data['room'])
        logger.info(f"User {user_id} joined room {data['room']}")

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(os.path.join(app.static_folder, 'js', 'fullcalendar'), exist_ok=True)
    os.makedirs(os.path.join(app.static_folder, 'js'), exist_ok=True)
    print(f"Server is running at http://localhost:5000/ - Click to open: http://localhost:5000/")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)