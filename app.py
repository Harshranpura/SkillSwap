

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime, timedelta
import re
import os
from dotenv import load_dotenv
from bson import ObjectId
from werkzeug.utils import secure_filename
import uuid
import logging
from flask_socketio import SocketIO, emit, join_room, leave_room
import socket
import stripe
from werkzeug.datastructures import FileStorage
from opencage.geocoder import OpenCageGeocode

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, static_folder="public", template_folder="src/pages")
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(24))
app.config.update({
    'SESSION_COOKIE_SECURE': False,  # Set to True in production with HTTPS
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'UPLOAD_FOLDER': os.path.abspath(os.path.join(os.path.dirname(__file__), 'Uploads')),
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB max upload size
    'STRIPE_SECRET_KEY': os.getenv('STRIPE_SECRET_KEY'),
    'STRIPE_PUBLISHABLE_KEY': os.getenv('STRIPE_PUBLISHABLE_KEY'),
    'STRIPE_WEBHOOK_SECRET': os.getenv('STRIPE_WEBHOOK_SECRET'),
})

# Initialize Flask extensions
bcrypt = Bcrypt(app)
socketio = SocketIO(app)
stripe.api_key = app.config['STRIPE_SECRET_KEY']

# Initialize OpenCage Geocoder
geocoder = OpenCageGeocode(os.getenv('OPENCAGE_API_KEY'))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB connection
try:
    mongo_client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017/SkillSwap"), serverSelectionTimeoutMS=5000)
    mongo_client.server_info()
    db = mongo_client['SkillSwap']
    users_collection = db['Users']
    skills_collection = db['Skills']
    feedback_collection = db['Feedback']
    availability_collection = db['Availability']
    messages_collection = db['Messages']
    connection_requests_collection = db['ConnectionRequests']
    contracts_collection = db['Contracts']
    ads_collection = db['Ads']
    payments_collection = db['Payments']

# Create indexes for performance
    users_collection.create_index([('email', 1)], unique=True)
    ads_collection.create_index([('status', 1), ('expires_at', 1)])
    contracts_collection.create_index([('status', 1), ('sender_id', 1), ('receiver_id', 1)])
    payments_collection.create_index([('contract_id', 1), ('type', 1)])
    feedback_collection.create_index([('user_id', 1), ('created_at', 1)])

except Exception as e:
    logger.error(f"Database connection failed: {e}")
    exit(1)



# Helper functions
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

def find_available_port(host='0.0.0.0', start_port=5000, max_attempts=10):
    port = start_port
    for i in range(max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                logger.info(f"Port {port} is available")
                return port
        except OSError as e:
            logger.warning(f"Port {port} is in use: {e}")
            port += 1
    raise Exception(f"No available ports found between {start_port} and {start_port + max_attempts - 1}")

# Routes for serving HTML pages


# Admin page route
@app.route('/admin')
def admin_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not user or user.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized: Super admin access required'}), 403
    return render_template('admin.html')


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

@app.route('/profile-view.html')
def profile_view_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('profile-view.html')

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

@app.route('/settings.html')
def setting_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('settings.html')

@app.route('/settings.html')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('settings.html')

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

@app.route('/<path:path>')
def serve_static(path):
    return app.send_static_file(path)

# ======================
# Dashboard & Ads System
# ======================
@app.route('/api/user_stats', methods=['GET'])
def get_user_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user_id']
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        active_ads = ads_collection.count_documents({
            'user_id': user_id,
            'status': 'active',
            'expires_at': {'$gt': datetime.utcnow()}
        })
        
        completed_contracts = contracts_collection.count_documents({
            '$or': [
                {'sender_id': user_id},
                {'receiver_id': user_id}
            ],
            'status': 'completed'
        })
        
        return jsonify({
            'skill_hours': user.get('skill_hours', 0),
            'active_ads': active_ads,
            'total_swaps': completed_contracts,
            'community_rating': user.get('rating', 0)
        })
    except Exception as e:
        logger.error(f"Error fetching user stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ads', methods=['GET'])
def get_ads():
    try:
        ads = list(ads_collection.find({
            'status': 'active',
            'expires_at': {'$gt': datetime.utcnow()}
        }).sort('created_at', -1).limit(50))
        
        return jsonify([{
            'id': str(ad['_id']),
            'title': ad['title'],
            'description': ad['description'],
            'user_id': ad['user_id'],
            'user_name': ad.get('user_name', 'Unknown'),
            'image': ad.get('image', ''),
            'video': ad.get('video', ''),
            'created_at': ad['created_at'].isoformat(),
            'expires_at': ad['expires_at'].isoformat()
            } for ad in ads])
        
    except Exception as e:
        logger.error(f"Error fetching ads: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/submit_ad', methods=['POST'])
def submit_ad():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user_id']
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        skill_hours = user.get('skill_hours', 0)
        if skill_hours < 10:
            return jsonify({
                'error': f'Not enough skill hours. You have {skill_hours}, but 10 are required.'
            }), 400
            
        return jsonify({
            'message': 'You are eligible to submit an ad. Please email your ad materials (image and .mp4 video) to ads@skillswap.com.'
        })
    except Exception as e:
        logger.error(f"Error checking ad submission eligibility: {e}")
        return jsonify({'error': str(e)}), 500
    

# API route to get all users
@app.route('/api/users', methods=['GET'])
def get_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not user or user.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        users = list(users_collection.find())
        return jsonify([{
            'id': str(user['_id']),
            'full_name': user['full_name'],
            'skill_hours': user.get('skill_hours', 0),
            'skills': user.get('skills', []),
            'location': user.get('location', 'Remote')
        } for user in users])
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return jsonify({'error': str(e)}), 500



# API route to update user
@app.route('/api/update_user/<user_id>', methods=['PUT'])
def update_user(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    try:
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {
                'full_name': data.get('full_name'),
                'skill_hours': int(data.get('skill_hours')),
                'location': data.get('location')
            }}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'message': 'User updated successfully'})
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        return jsonify({'error': str(e)}), 500



# API route to delete user
@app.route('/api/delete_user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        result = users_collection.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'message': 'User deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return jsonify({'error': str(e)}), 500

# API route for admin to upload ads
@app.route('/api/admin/upload_ad', methods=['POST'])
def upload_ad():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    required_fields = ['title', 'description', 'image', 'video', 'user_id']
    if not all(data.get(field) for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    try:
        user = users_collection.find_one({'_id': ObjectId(data['user_id'])})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        ad = {
            'title': data['title'],
            'description': data['description'],
            'user_id': data['user_id'],
            'user_name': user['full_name'],
            'image': data['image'],
            'video': data['video'],
            'status': data.get('status', 'active'),
            'created_at': datetime.utcnow(),
            'expires_at': datetime.fromisoformat(data['expires_at'])
        }
        result = ads_collection.insert_one(ad)
        return jsonify({'message': 'Ad uploaded successfully', 'ad_id': str(result.inserted_id)})
    except Exception as e:
        logger.error(f"Error uploading ad: {e}")
        return jsonify({'error': str(e)}), 500



# API route for admin to delete ads
@app.route('/api/admin/delete_ad/<ad_id>', methods=['DELETE'])
def delete_ad(ad_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        result = ads_collection.delete_one({'_id': ObjectId(ad_id)})
        if result.deleted_count == 0:
            return jsonify({'error': 'Ad not found'}), 404
        return jsonify({'message': 'Ad deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting ad: {e}")
        return jsonify({'error': str(e)}), 500



# API route to get platform analytics
@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        total_users = users_collection.count_documents({})
        active_swaps = contracts_collection.count_documents({'status': 'active'})
        total_skill_hours = sum(user.get('skill_hours', 0) for user in users_collection.find())
        total_revenue = sum(payment.get('amount', 0) for payment in payments_collection.find({'type': 'platform_fee'})) / 100
        total_contracts = contracts_collection.count_documents({})
        pending_payments = payments_collection.count_documents({'status': 'held'})
        return jsonify({
            'total_users': total_users,
            'active_swaps': active_swaps,
            'total_skill_hours': total_skill_hours,
            'total_revenue': total_revenue,
            'total_contracts': total_contracts,
            'pending_payments': pending_payments
        })
    except Exception as e:
        logger.error(f"Error fetching analytics: {e}")
        return jsonify({'error': str(e)}), 500


# ======================
# Escrow Payment System
# ======================
@app.route('/api/create_payment_intent', methods=['POST'])
def create_payment_intent():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # $15.00 in cents
        amount = 1500
        
        # Create PaymentIntent
        intent = stripe.PaymentIntent.create(
            amount=amount,
            currency='usd',
            payment_method_types=['card'],
            metadata={
                'user_id': session['user_id'],
                'purpose': 'skillswap_escrow'
            }
        )
        
        return jsonify({
            'clientSecret': intent['client_secret'],
            'paymentIntentId': intent['id']
        })
    except Exception as e:
        logger.error(f"Error creating payment intent: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/confirm_escrow_payment', methods=['POST'])
def confirm_escrow_payment():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    required_fields = ['contract_id', 'payment_intent_id']
    if error := validate_user_input(data, required_fields):
        return jsonify({'error': error}), 400
    
    user_id = session['user_id']
    contract_id = data['contract_id']
    payment_intent_id = data['payment_intent_id']
    
    try:
        # Verify payment was successful
        intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        if intent.status != 'succeeded':
            return jsonify({'error': 'Payment not completed'}), 400
        
        # Check contract exists
        contract = contracts_collection.find_one({'_id': ObjectId(contract_id)})
        if not contract:
            return jsonify({'error': 'Contract not found'}), 404
        
        # Determine if this is sender or receiver payment
        is_sender = contract['sender_id'] == user_id
        payment_field = 'sender_payment' if is_sender else 'receiver_payment'
        
        # Update contract with payment info
        contracts_collection.update_one(
            {'_id': ObjectId(contract_id)},
            {'$set': {
                f'escrow.{payment_field}': {
                    'payment_intent_id': payment_intent_id,
                    'amount': 1500,  # $15.00
                    'status': 'held',
                    'timestamp': datetime.utcnow()
                },
                'status': 'active' if is_sender and contract.get('escrow', {}).get('receiver_payment') else contract['status']
            }}
        )
        
        # Record payment in payments collection
        payments_collection.insert_one({
            'user_id': user_id,
            'contract_id': contract_id,
            'payment_intent_id': payment_intent_id,
            'amount': 1500,
            'type': 'escrow_deposit',
            'status': 'held',
            'created_at': datetime.utcnow()
        })
        
        # Notify both parties via Socket.IO if both payments are complete
        if is_sender and contract.get('escrow', {}).get('receiver_payment'):
            socketio.emit('contract_activated', {
                'contract_id': contract_id,
                'message': 'Both escrow payments received, contract is now active'
            }, room=contract['sender_id'])
            
            socketio.emit('contract_activated', {
                'contract_id': contract_id,
                'message': 'Both escrow payments received, contract is now active'
            }, room=contract['receiver_id'])
        
        return jsonify({'message': 'Escrow payment confirmed'})
    except Exception as e:
        logger.error(f"Error confirming escrow payment: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/release_escrow', methods=['POST'])
def release_escrow():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    required_fields = ['contract_id']
    if error := validate_user_input(data, required_fields):
        return jsonify({'error': error}), 400
    
    contract_id = data['contract_id']
    
    try:
        contract = contracts_collection.find_one({'_id': ObjectId(contract_id)})
        if not contract:
            return jsonify({'error': 'Contract not found'}), 404
        
        if contract.get('status') != 'completed':
            contracts_collection.update_one(
                {'_id': ObjectId(contract_id)},
                {'$set': {
                    'status': 'completed',
                    'completed_at': datetime.utcnow()
                }}
            )
        
        refund_amount = 1250  # $12.50 in cents
        sender_payment = contract.get('escrow', {}).get('sender_payment')
        receiver_payment = contract.get('escrow', {}).get('receiver_payment')
        
        if not sender_payment or not receiver_payment:
            return jsonify({'error': 'Escrow payments not fully held'}), 400
        
        sender_refund = stripe.Refund.create(
            payment_intent=sender_payment['payment_intent_id'],
            amount=refund_amount
        )
        receiver_refund = stripe.Refund.create(
            payment_intent=receiver_payment['payment_intent_id'],
            amount=refund_amount
        )
        
        contracts_collection.update_one(
            {'_id': ObjectId(contract_id)},
            {'$set': {
                'escrow.sender_payment.status': 'refunded',
                'escrow.receiver_payment.status': 'refunded',
                'escrow.sender_refund_id': sender_refund.id,
                'escrow.receiver_refund_id': receiver_refund.id
            }}
        )
        
        payments_collection.update_many(
            {
                'contract_id': contract_id,
                'type': 'escrow_deposit'
            },
            {'$set': {
                'status': 'refunded',
                'refund_amount': refund_amount,
                'refunded_at': datetime.utcnow()
            }}
        )
        
        payments_collection.insert_one({
            'contract_id': contract_id,
            'amount': 500,  # $5.00
            'type': 'platform_fee',
            'status': 'completed',
            'created_at': datetime.utcnow()
        })
        
        socketio.emit('payment_refunded', {
            'contract_id': contract_id,
            'sender_id': contract['sender_id'],
            'receiver_id': contract['receiver_id']
        }, room=contract['sender_id'])
        socketio.emit('payment_refunded', {
            'contract_id': contract_id,
            'sender_id': contract['sender_id'],
            'receiver_id': contract['receiver_id']
        }, room=contract['receiver_id'])
        
        return jsonify({'message': 'Escrow funds released successfully'})
    except Exception as e:
        logger.error(f"Error releasing escrow: {e}")
        return jsonify({'error': str(e)}), 500

# Stripe webhook handler
@app.route('/stripe_webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, app.config['STRIPE_WEBHOOK_SECRET']
        )
    except ValueError as e:
        # Invalid payload
        return jsonify({'error': str(e)}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return jsonify({'error': str(e)}), 400
    
    # Handle the event
    if event['type'] == 'payment_intent.succeeded':
        payment_intent = event['data']['object']
        logger.info(f"Payment succeeded: {payment_intent['id']}")
    elif event['type'] == 'payment_intent.payment_failed':
        payment_intent = event['data']['object']
        logger.error(f"Payment failed: {payment_intent['id']}")
    elif event['type'] == 'charge.refunded':
        charge = event['data']['object']
        logger.info(f"Refund processed: {charge['id']}")
    
    return jsonify({'success': True})

# ======================
# Settings Page Endpoints
# ======================

@app.route('/api/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    allowed_fields = ['full_name', 'email', 'bio', 'location', 'privacy_settings']
    update_data = {k: v for k in allowed_fields if (v := data.get(k)) is not None}
    
    # Handle location geocoding
    if 'location' in update_data and update_data['location'] and update_data['location'].lower() != 'remote':
        try:
            results = geocoder.geocode(update_data['location'])
            if results and len(results) > 0:
                update_data['coordinates'] = {
                    'latitude': results[0]['geometry']['lat'],
                    'longitude': results[0]['geometry']['lng']
                }
            else:
                logger.warning(f"No geocoding results for location: {update_data['location']}")
                update_data['coordinates'] = None
        except Exception as e:
            logger.error(f"Geocoding error for location {update_data['location']}: {e}")
            update_data['coordinates'] = None
    elif update_data.get('location', '').lower() == 'remote':
        update_data['coordinates'] = None
    
    if not update_data:
        return jsonify({'error': 'No valid fields to update'}), 400
    
    user_id = session.get('user_id')
    try:
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({'message': 'Profile updated successfully'})
    except Exception as e:
        logger.error(f"Error updating profile: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/update_password', methods=['POST'])
def update_password():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    required_fields = ['current_password', 'new_password']
    if error := validate_user_input(data, required_fields):
        return jsonify({'error': error}), 400
    
    if not validate_password(data['new_password']):
        return jsonify({'error': 'New password does not meet requirements'}), 400
    
    user_id = session.get('user_id')
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        if not bcrypt.check_password_hash(user['password_hash'], data['current_password']):
            return jsonify({'error': 'Current password is incorrect'}), 400
            
        new_hash = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'password_hash': new_hash}}
        )
        
        return jsonify({'message': 'Password updated successfully'})
    except Exception as e:
        logger.error(f"Error updating password: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/update_notifications', methods=['POST'])
def update_notifications():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid notification settings'}), 400
    
    user_id = session.get('user_id')
    try:
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'notification_settings': data}}
        )
        
        return jsonify({'message': 'Notification settings updated'})
    except Exception as e:
        logger.error(f"Error updating notifications: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    if not data.get('confirm'):
        return jsonify({'error': 'Confirmation required'}), 400
    
    user_id = session.get('user_id')
    try:
        # In production, you might want to anonymize data instead of deleting
        result = users_collection.delete_one({'_id': ObjectId(user_id)})
        
        if result.deleted_count == 0:
            return jsonify({'error': 'User not found'}), 404
            
        # Clean up session
        session.pop('user_id', None)
        
        return jsonify({
            'message': 'Account deleted successfully',
            'redirect': '/login.html'
        })
    except Exception as e:
        logger.error(f"Error deleting account: {e}")
        return jsonify({'error': str(e)}), 500

# API Routes
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
            'location': data.get('location', 'Remote'),
            'rating': 0,
            'notification_settings': {
                'messages': True,
                'connection_requests': True,
                'contract_updates': True
            }
        }
        result = users_collection.insert_one(user)
        user_id = str(result.inserted_id)
        session['user_id'] = user_id
        logger.info(f"Registered user with ID: {user_id}")
        return jsonify({
            'message': 'Registration successful',
            'redirect': '/profile.html',
            'user': {'id': user_id, 'full_name': user['full_name'], 'email': user['email']}
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
            user_id = str(user['_id'])
            session['user_id'] = user_id
            logger.info(f"Logged in user with ID: {user_id}, Session user_id: {session['user_id']}")
            return jsonify({
                'message': 'Login successful',
                'redirect': '/profile.html',
                'user': {'id': user_id, 'full_name': user['full_name'], 'email': user['email']}
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
                'skill_role': skill.get('skill_role', 'offered'),
                'experience_level': skill.get('experience_level', ''),
                'skill_type': skill.get('skill_type', ''),
                'specialties': skill.get('specialties', ''),
                'availability': skill.get('availability', ''),
                'certifications': skill.get('certifications', ''),
                'description': skill.get('description', ''),
                'portfolio': skill.get('portfolio', '')
            } for skill in skills],
            'skill_hours': user.get('skill_hours', 0),
            'location': user.get('location', 'Remote'),
            'id': str(user['_id']),
            'rating': user.get('rating', 0),
            'notification_settings': user.get('notification_settings', {})
        })
    except Exception as e:
        logger.error(f"Profile fetch error: {e}")
        return jsonify({'error': str(e)}), 500
    
    

@app.route('/api/profile/<user_id>', methods=['GET'])
def get_user_profile(user_id):
    try:
        if 'user_id' not in session:
            logger.error("Unauthorized access to /api/profile/<user_id>: No user_id in session")
            return jsonify({'error': 'Unauthorized'}), 401

        if not re.match(r'^[0-9a-fA-F]{24}$', user_id):
            logger.error(f"Invalid user_id format: {user_id}")
            return jsonify({'error': 'Invalid user ID format'}), 400

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
                'skill_role': skill.get('skill_role', 'offered'),
                'experience_level': skill.get('experience_level', ''),
                'skill_type': skill.get('skill_type', ''),
                'specialties': skill.get('specialties', ''),
                'availability': skill.get('availability', ''),
                'certifications': skill.get('certifications', ''),
                'description': skill.get('description', ''),
                'portfolio': skill.get('portfolio', '')
            } for skill in skills],
            'skill_hours': user.get('skill_hours', 0),
            'location': user.get('location', 'Remote'),
            'id': str(user['_id']),
            'rating': user.get('rating', 0)
        })
    except Exception as e:
        logger.error(f"Profile fetch error for user_id {user_id}: {e}")
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

@app.route('/api/add_skill', methods=['POST'])
def add_skill():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        required_fields = ['skill_name', 'skill_role']
        if data.get('skill_role') == 'offered':
            required_fields.extend(['experience_level', 'skill_type', 'specialties', 'availability'])

        if error := validate_user_input(data, required_fields):
            return jsonify({'error': error}), 400

        user_id = session.get('user_id')
        skill = {
            'user_id': user_id,
            'skill_name': data['skill_name'],
            'skill_role': data['skill_role'],
            'created_at': datetime.utcnow()
        }

        if data['skill_role'] == 'offered':
            skill.update({
                'experience_level': data['experience_level'],
                'skill_type': data['skill_type'],
                'specialties': data['specialties'],
                'availability': data['availability'],
                'certifications': data.get('certifications', ''),
                'description': data.get('description', ''),
                'portfolio': data.get('portfolio', '')
            })

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
        skill_role = data.get('skill_role')
        update_data = {
            'skill_name': data.get('skill_name'),
            'skill_role': skill_role
        }

        if skill_role == 'offered':
            update_data.update({
                k: v for k in [
                    'experience_level', 'skill_type', 'specialties', 'availability',
                    'certifications', 'description', 'portfolio'
                ] if (v := data.get(k)) is not None
            })

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
    

# Add this at the top of your app.py file
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'webm', 'mov', 'pdf', 'doc', 'docx'}

def allowed_file(filename):
    logger.info(f"Checking file: {filename}, extension: {filename.rsplit('.', 1)[1].lower() if '.' in filename else 'None'}")
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# General file upload route for admin page
@app.route('/api/upload_file', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
    
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'}), 400
    
    try:
        # Create upload folder if it doesn't exist
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        filename = unique_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        relative_path = f'/uploads/{filename}'
        return jsonify({'message': 'File uploaded successfully', 'path': relative_path})
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return jsonify({'error': f'Error uploading file: {str(e)}'}), 500

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
        skill_offered = data.get('skill_offered', '').lower().strip()
        skill_required = data.get('skill_required', '').lower().strip()
        skill_type = data.get('skill_type', 'all')
        experience_levels = data.get('experience_levels', [])
        location = data.get('location', '').lower()

        current_user_id = session['user_id']
        users = list(users_collection.find({'_id': {'$ne': ObjectId(current_user_id)}}))
        matched_users = []

        for user in users:
            user_skills = list(skills_collection.find({'user_id': str(user['_id'])}))
            if not user_skills:
                continue

            offers_required = (not skill_required) or any(
                skill_required in skill['skill_name'].lower() and skill.get('skill_role') == 'offered'
                for skill in user_skills
            )
            needs_offered = (not skill_offered) or any(
                skill_offered in skill['skill_name'].lower() and skill.get('skill_role') == 'required'
                for skill in user_skills
            )

            offered_skills = [skill for skill in user_skills if skill.get('skill_role') == 'offered']
            matches_skill_type = skill_type == 'all' or any(
                skill.get('skill_type', 'N/A') == skill_type for skill in offered_skills
            )
            matches_experience = not experience_levels or any(
                skill.get('experience_level', '') in experience_levels for skill in offered_skills
            )
            matches_location = not location or location in user.get('location', 'Remote').lower()

            if offers_required and needs_offered and matches_skill_type and matches_experience and matches_location:
                connection = connection_requests_collection.find_one({
                    '$or': [
                        {'sender_id': current_user_id, 'receiver_id': str(user['_id'])},
                        {'sender_id': str(user['_id']), 'receiver_id': current_user_id}
                    ]
                })
                connection_status = 'none'
                if connection:
                    connection_status = connection['status']

                matched_users.append({
                    'id': str(user['_id']),
                    'full_name': user['full_name'],
                    'profile_picture': user.get('profile_picture', ''),
                    'skills': [{
                        'skill_id': str(skill['_id']),
                        'skill_name': skill['skill_name'],
                        'skill_role': skill.get('skill_role', 'offered'),
                        'experience_level': skill.get('experience_level', ''),
                        'skill_type': skill.get('skill_type', ''),
                        'specialties': skill.get('specialties', ''),
                        'availability': skill.get('availability', ''),
                        'certifications': skill.get('certifications', ''),
                        'description': skill.get('description', ''),
                        'portfolio': skill.get('portfolio', '')
                    } for skill in user_skills],
                    'skill_hours': user.get('skill_hours', 0),
                    'location': user.get('location', 'Remote'),
                    'coordinates': user.get('coordinates', None),  # Include coordinates
                    'connection_status': connection_status
                })

        logger.info(f"Search completed with skill_offered: {skill_offered}, skill_required: {skill_required}, "
                   f"skill_type: {skill_type}, experience: {experience_levels}, location: {location}")
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

        if not users_collection.find_one({'_id': ObjectId(receiver_id)}):
            return jsonify({'error': 'Receiver not found'}), 404

        connection = connection_requests_collection.find_one({
            '$or': [
                {'sender_id': sender_id, 'receiver_id': receiver_id, 'status': 'accepted'},
                {'sender_id': receiver_id, 'receiver_id': sender_id, 'status': 'accepted'}
            ]
        })
        if not connection:
            return jsonify({'error': 'You must be connected to send messages'}), 403

        message_doc = {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'message': message,
            'timestamp': datetime.utcnow(),
            'unread': True
        }
        result = messages_collection.insert_one(message_doc)
        contract_id = str(result.inserted_id)

        sender = users_collection.find_one({'_id': ObjectId(sender_id)})
        socketio.emit('new_message', {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'message': message,
            'timestamp': message_doc['timestamp'].isoformat()
        }, room=receiver_id)

        socketio.emit('refresh_chat_list', {}, room=sender_id)
        socketio.emit('refresh_chat_list', {}, room=receiver_id)

        return jsonify({'message': 'Message sent successfully'})
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/mark_messages_read', methods=['POST'])
def mark_messages_read():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        sender_id = request.args.get('sender_id')
        if not sender_id:
            return jsonify({'error': 'Sender ID is required'}), 400

        receiver_id = session.get('user_id')

        if not users_collection.find_one({'_id': ObjectId(sender_id)}):
            return jsonify({'error': 'Sender not found'}), 404

        result = messages_collection.update_many(
            {'sender_id': sender_id, 'receiver_id': receiver_id, 'unread': True},
            {'$set': {'unread': False}}
        )

        socketio.emit('refresh_chat_list', {}, room=sender_id)
        socketio.emit('refresh_chat_list', {}, room=receiver_id)

        logger.info(f"Marked {result.modified_count} messages as read from {sender_id} to {receiver_id}")
        return jsonify({'message': 'Messages marked as read', 'modified_count': result.modified_count}), 200
    except Exception as e:
        logger.error(f"Error marking messages as read: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat_list', methods=['GET'])
def get_chat_list():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        user_id = session.get('user_id')
        if not isinstance(user_id, str) or not re.match(r'^[0-9a-fA-F]{24}$', user_id):
            logger.error(f"Invalid user_id in session: {user_id}")
            return jsonify({'error': 'Invalid user ID in session'}), 400

        connections = list(connection_requests_collection.find({
            '$or': [
                {'sender_id': user_id, 'status': 'accepted'},
                {'receiver_id': user_id, 'status': 'accepted'}
            ]
        }))

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

        connected_user_ids = set()
        for conn in connections:
            other_user_id = conn['receiver_id'] if conn['sender_id'] == user_id else conn['sender_id']
            connected_user_ids.add(other_user_id)

        chat_list = []
        for conv in conversations:
            try:
                user = users_collection.find_one({'_id': ObjectId(conv['_id'])})
            except Exception as e:
                logger.error(f"Invalid user ID in conversation: {conv['_id']}, error: {e}")
                continue

            if user:
                unread_count = messages_collection.count_documents({
                    'sender_id': str(conv['_id']),
                    'receiver_id': user_id,
                    'unread': True
                })

                chat_list.append({
                    'user_id': str(conv['_id']),
                    'user_name': user['full_name'],
                    'profile_picture': user.get('profile_picture', ''),
                    'last_message': conv['last_message'],
                    'unread_count': unread_count
                })
                connected_user_ids.discard(str(conv['_id']))

        for user_id in connected_user_ids:
            user = users_collection.find_one({'_id': ObjectId(user_id)})
            if user:
                chat_list.append({
                    'user_id': str(user['_id']),
                    'user_name': user['full_name'],
                    'profile_picture': user.get('profile_picture', ''),
                    'last_message': 'Start chatting!',
                    'unread_count': 0
                })

        return jsonify(chat_list)
    except Exception as e:
        logger.error(f"Error fetching chat list: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/send_connection_request', methods=['POST'])
def send_connection_request():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        if error := validate_user_input(data, ['receiver_id']):
            return jsonify({'error': error}), 400

        sender_id = session.get('user_id')
        receiver_id = data['receiver_id']

        if sender_id == receiver_id:
            return jsonify({'error': 'Cannot send request to yourself'}), 400

        if not users_collection.find_one({'_id': ObjectId(receiver_id)}):
            return jsonify({'error': 'Receiver not found'}), 404

        existing_request = connection_requests_collection.find_one({
            '$or': [
                {'sender_id': sender_id, 'receiver_id': receiver_id},
                {'sender_id': receiver_id, 'receiver_id': sender_id}
            ]
        })
        if existing_request:
            return jsonify({'error': 'Connection request already exists'}), 400

        request_doc = {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'status': 'pending',
            'created_at': datetime.utcnow()
        }
        result = connection_requests_collection.insert_one(request_doc)
        logger.info(f"Connection request sent from {sender_id} to {receiver_id}, request_id: {result.inserted_id}")

        sender = users_collection.find_one({'_id': ObjectId(sender_id)})
        socketio.emit('new_connection_request', {
            'request_id': str(result.inserted_id),
            'sender_id': sender_id,
            'sender_name': sender['full_name'],
            'sender_profile_picture': sender.get('profile_picture', '')
        }, room=receiver_id)

        socketio.emit('refresh_search', {}, room=sender_id)
        socketio.emit('refresh_search', {}, room=receiver_id)

        return jsonify({'message': 'Connection request sent successfully', 'request_id': str(result.inserted_id)})
    except Exception as e:
        logger.error(f"Error sending connection request: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/connection_requests', methods=['GET'])
def get_connection_requests():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        user_id = session.get('user_id')
        requests = list(connection_requests_collection.find({'receiver_id': user_id, 'status': 'pending'}))

        enriched_requests = []
        for req in requests:
            sender = users_collection.find_one({'_id': ObjectId(req['sender_id'])})
            if sender:
                enriched_requests.append({
                    'request_id': str(req['_id']),
                    'sender_id': req['sender_id'],
                    'sender_name': sender['full_name'],
                    'sender_profile_picture': sender.get('profile_picture', ''),
                    'created_at': req['created_at'].isoformat()
                })

        return jsonify(enriched_requests)
    except Exception as e:
        logger.error(f"Error fetching connection requests: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/accept_connection_request', methods=['POST'])
def accept_connection_request():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        if error := validate_user_input(data, ['request_id']):
            return jsonify({'error': error}), 400

        user_id = session.get('user_id')
        request_id = data['request_id']

        request_doc = connection_requests_collection.find_one({'_id': ObjectId(request_id), 'receiver_id': user_id, 'status': 'pending'})
        if not request_doc:
            return jsonify({'error': 'Request not found or not authorized'}), 404

        result = connection_requests_collection.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': {'status': 'accepted', 'accepted_at': datetime.utcnow()}}
        )

        if result.matched_count == 0:
            return jsonify({'error': 'Request not found or already processed'}), 404

        sender_id = request_doc['sender_id']
        receiver_id = user_id

        socketio.emit('request_accepted', {
            'request_id': request_id,
            'sender_id': sender_id,
            'receiver_id': receiver_id
        }, room=sender_id)

        socketio.emit('request_accepted', {
            'request_id': request_id,
            'sender_id': sender_id,
            'receiver_id': receiver_id
        }, room=receiver_id)

        socketio.emit('refresh_chat_list', {}, room=sender_id)
        socketio.emit('refresh_chat_list', {}, room=receiver_id)

        socketio.emit('refresh_search', {}, room=sender_id)
        socketio.emit('refresh_search', {}, room=receiver_id)

        logger.info(f"Connection request {request_id} accepted by {receiver_id} from {sender_id}")
        return jsonify({'message': 'Connection request accepted'})
    except Exception as e:
        logger.error(f"Error accepting connection request: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/connection_status', methods=['GET'])
def connection_status():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        receiver_id = request.args.get('receiver_id')
        if not receiver_id:
            return jsonify({'error': 'Receiver ID is required'}), 400

        sender_id = session.get('user_id')
        connection = connection_requests_collection.find_one({
            '$or': [
                {'sender_id': sender_id, 'receiver_id': receiver_id},
                {'sender_id': receiver_id, 'receiver_id': sender_id}
            ]
        })

        if not connection:
            return jsonify({'status': 'none'})

        return jsonify({'status': connection['status']})
    except Exception as e:
        logger.error(f"Error fetching connection status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notify_requester', methods=['POST'])
def notify_requester():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        if error := validate_user_input(data, ['requester_id']):
            return jsonify({'error': error}), 400

        requester_id = data['requester_id']
        socketio.emit('refresh_chat_list', {}, room=requester_id)
        logger.info(f"Notified requester {requester_id} to refresh chat list")
        return jsonify({'message': 'Requester notified'})
    except Exception as e:
        logger.error(f"Error notifying requester: {e}")
        return jsonify({'error': str(e)}), 500

# Contract-Related Routes (Updated for Mutual Skill Swap)
@app.route('/api/generate_contract', methods=['POST'])
def generate_contract():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        required_fields = ['receiver_id', 'sender_skill_offered', 'receiver_skill_offered', 'total_sessions', 'session_duration', 'frequency', 'mode']
        if error := validate_user_input(data, required_fields):
            return jsonify({'error': error}), 400

        sender_id = session['user_id']
        receiver_id = data['receiver_id']

        if sender_id == receiver_id:
            return jsonify({'error': 'Cannot create contract with yourself'}), 400

        if not users_collection.find_one({'_id': ObjectId(receiver_id)}):
            return jsonify({'error': 'Receiver not found'}), 404

        connection = connection_requests_collection.find_one({
            '$or': [
                {'sender_id': sender_id, 'receiver_id': receiver_id, 'status': 'accepted'},
                {'sender_id': receiver_id, 'receiver_id': sender_id, 'status': 'accepted'}
            ]
        })
        if not connection:
            return jsonify({'error': 'You must be connected to generate a contract'}), 403

        contract = {
            'sender_id': sender_id,
            'receiver_id': receiver_id,
            'sender_skill_offered': data['sender_skill_offered'],
            'receiver_skill_offered': data['receiver_skill_offered'],
            'skill_levels': {
                'sender': data.get('sender_skill_level', 'Intermediate'),
                'receiver': data.get('receiver_skill_level', 'Intermediate')
            },
            'skill_descriptions': {
                'sender': data.get('sender_skill_description', ''),
                'receiver': data.get('receiver_skill_description', '')
            },
            'total_sessions': int(data['total_sessions']),
            'sender_sessions_completed': 0,
            'receiver_sessions_completed': 0,
            'session_duration': int(data['session_duration']),
            'frequency': data['frequency'],
            'schedule': data.get('schedule', []),  # List of dicts: [{"skill": "sender_skill", "time": "..."}, ...]
            'mode': data['mode'],
            'platform': data.get('platform', ''),
            'location': data.get('location', '' if data['mode'] != 'In-person' else 'TBD'),
            'terms': data.get('terms', ''),
            'prerequisites': data.get('prerequisites', ''),
            'deliverables': data.get('deliverables', ''),
            'cancellation_policy': data.get('cancellation_policy', '24-hour notice required'),
            'status': 'pending',
            'sender_confirmed_finish': False,
            'receiver_confirmed_finish': False,
            'sender_feedback': None,
            'receiver_feedback': None,
            'hours_spent': 0,
            'dispute_process': data.get('dispute_process', 'Mediation via SkillSwap admin'),
            'termination_clause': data.get('termination_clause', 'Mutual agreement or violation of terms'),
            'skill_hours_exchange': int(data.get('skill_hours_exchange', data['total_sessions'])),
            'created_at': datetime.utcnow(),
            'accepted_at': None,
            'completed_at': None,
            'escrow': {
                'sender_payment': None,
                'receiver_payment': None
            }
        }
        result = contracts_collection.insert_one(contract)
        contract_id = str(result.inserted_id)

        sender = users_collection.find_one({'_id': ObjectId(sender_id)})
        socketio.emit('new_contract', {
            'contract_id': contract_id,
            'sender_id': sender_id,
            'sender_name': sender['full_name'],
            'sender_skill_offered': data['sender_skill_offered'],
            'receiver_skill_offered': data['receiver_skill_offered']
        }, room=receiver_id)

        logger.info(f"Contract generated by {sender_id} for {receiver_id}, contract_id: {contract_id}")
        return jsonify({'message': 'Contract generated successfully', 'contract_id': contract_id})
    except Exception as e:
        logger.error(f"Error generating contract: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/accept_contract', methods=['POST'])
def accept_contract():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json()
        if error := validate_user_input(data, ['contract_id']):
            return jsonify({'error': error}), 400

        user_id = session['user_id']
        contract_id = data['contract_id']

        contract = contracts_collection.find_one({
            '_id': ObjectId(contract_id),
            'receiver_id': user_id,
            'status': 'pending'
        })
        if not contract:
            return jsonify({'error': 'Contract not found or not authorized'}), 404

        result = contracts_collection.update_one(
            {'_id': ObjectId(contract_id)},
            {'$set': {'status': 'active', 'accepted_at': datetime.utcnow()}}
        )
        if result.modified_count == 0:
            return jsonify({'error': 'Contract not updated'}), 500

        socketio.emit('contract_accepted', {
            'contract_id': contract_id,
            'receiver_id': user_id
        }, room=contract['sender_id'])

        logger.info(f"Contract {contract_id} accepted by {user_id}")
        return jsonify({'message': 'Contract accepted successfully'})
    except Exception as e:
        logger.error(f"Error accepting contract: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/mark_session_complete', methods=['POST'])
def mark_session_complete():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'User not logged in'}), 401

        user_id = session['user_id']
        data = request.get_json()
        contract_id = data.get('contract_id')
        skill_type = data.get('skill_type')  # 'sender_skill' or 'receiver_skill'

        if not contract_id or not skill_type:
            return jsonify({'error': 'Contract ID and skill type are required'}), 400

        contract = contracts_collection.find_one({'_id': ObjectId(contract_id)})
        if not contract:
            return jsonify({'error': 'Contract not found'}), 404

        if contract['sender_id'] != user_id and contract['receiver_id'] != user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        if contract['status'] != 'active':
            return jsonify({'error': 'Contract is not active'}), 400

        # Determine which session counter to increment
        is_sender = contract['sender_id'] == user_id
        if (is_sender and skill_type == 'sender_skill') or (not is_sender and skill_type == 'receiver_skill'):
            field_to_increment = 'sender_sessions_completed' if skill_type == 'sender_skill' else 'receiver_sessions_completed'
        else:
            return jsonify({'error': 'Invalid skill type for this user'}), 400

        # Increment the session counter
        updated_contract = contracts_collection.find_one_and_update(
            {'_id': ObjectId(contract_id)},
            {'$inc': {field_to_increment: 1}},
            return_document=True
        )

        # Update hours spent
        hours_spent = (updated_contract['session_duration'] * (updated_contract['sender_sessions_completed'] + updated_contract['receiver_sessions_completed'])) / 60
        contracts_collection.update_one(
            {'_id': ObjectId(contract_id)},
            {'$set': {'hours_spent': hours_spent}}
        )

        socketio.emit('session_updated', {'contract_id': contract_id}, room=contract['sender_id'])
        socketio.emit('session_updated', {'contract_id': contract_id}, room=contract['receiver_id'])

        return jsonify({
            'message': 'Session marked complete',
            'sender_sessions_completed': updated_contract['sender_sessions_completed'],
            'receiver_sessions_completed': updated_contract['receiver_sessions_completed'],
            'total_sessions': updated_contract['total_sessions']
        })
    except Exception as e:
        logger.error(f"Error marking session: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/finish_contract', methods=['POST'])
def finish_contract():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'User not logged in'}), 401

        user_id = session['user_id']
        data = request.get_json()
        contract_id = data.get('contract_id')

        if not contract_id:
            return jsonify({'error': 'Contract ID is required'}), 400

        contract = contracts_collection.find_one({'_id': ObjectId(contract_id)})
        if not contract:
            return jsonify({'error': 'Contract not found'}), 404

        if contract['sender_id'] != user_id and contract['receiver_id'] != user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        # Determine which user is requesting to finish
        is_sender = contract['sender_id'] == user_id
        update_field = 'sender_confirmed_finish' if is_sender else 'receiver_confirmed_finish'
        other_user_id = contract['receiver_id'] if is_sender else contract['sender_id']

        # Update the finish confirmation for the user
        contracts_collection.update_one(
            {'_id': ObjectId(contract_id)},
            {'$set': {update_field: True}}
        )

        # Check if both users have confirmed to finish
        updated_contract = contracts_collection.find_one({'_id': ObjectId(contract_id)})
        if updated_contract['sender_confirmed_finish'] and updated_contract['receiver_confirmed_finish']:
            # Update skill hours for both users upon completion
            total_hours = (updated_contract['session_duration'] * updated_contract['total_sessions']) / 60  # Convert minutes to hours
            skill_hours_exchange = total_hours  # For simplicity, skill hours = total hours

            # Update sender's skill hours
            users_collection.update_one(
                {'_id': ObjectId(updated_contract['sender_id'])},
                {'$inc': {'skill_hours': skill_hours_exchange}}
            )

            # Update receiver's skill hours
            users_collection.update_one(
                {'_id': ObjectId(updated_contract['receiver_id'])},
                {'$inc': {'skill_hours': skill_hours_exchange}}
            )

            # Mark contract as completed
            contracts_collection.update_one(
                {'_id': ObjectId(contract_id)},
                {'$set': {
                    'status': 'completed',
                    'completed_at': datetime.utcnow(),
                    'skill_hours_exchange': skill_hours_exchange
                }}
            )

            socketio.emit('contract_completed', {'contract_id': contract_id}, room=updated_contract['sender_id'])
            socketio.emit('contract_completed', {'contract_id': contract_id}, room=updated_contract['receiver_id'])
            logger.info(f"Contract {contract_id} fully completed, skill hours updated")
        else:
            socketio.emit('finish_requested', {'contract_id': contract_id}, room=other_user_id)
            logger.info(f"User {user_id} requested to finish contract {contract_id}")

        return jsonify({'message': 'Finish request submitted'})
    except Exception as e:
        logger.error(f"Error finishing contract: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get_contracts', methods=['GET'])
def get_contracts():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'User not logged in'}), 401

        user_id = session['user_id']
        contracts = contracts_collection.find({
            '$or': [
                {'sender_id': user_id},
                {'receiver_id': user_id}
            ]
        })

        contract_list = []
        for contract in contracts:
            # Determine the partner (other user)
            partner_id = contract['receiver_id'] if contract['sender_id'] == user_id else contract['sender_id']
            partner = users_collection.find_one({'_id': ObjectId(partner_id)})
            partner_name = partner['full_name'] if partner else 'Unknown User'

            # Handle old and new contract structures
            contract_data = {
                'contract_id': str(contract['_id']),
                'partner': partner_name,
                'status': contract.get('status', 'pending'),
                'sender_id': contract['sender_id'],
                'receiver_id': contract['receiver_id'],
                # New fields (with fallbacks for old contracts)
                'sender_skill_offered': contract.get('sender_skill_offered', contract.get('skill', 'Unknown Skill')),
                'receiver_skill_offered': contract.get('receiver_skill_offered', 'Unknown Skill'),
                'total_sessions': contract.get('total_sessions', contract.get('sessions', 0)),
                'sender_sessions_completed': contract.get('sender_sessions_completed', contract.get('completed_sessions', 0)),
                'receiver_sessions_completed': contract.get('receiver_sessions_completed', 0),
                'session_duration': contract.get('session_duration', 60),  # Default to 60 minutes
                'frequency': contract.get('frequency', 'weekly'),
                'mode': contract.get('mode', 'online'),
                'platform': contract.get('platform', ''),
                'location': contract.get('location', ''),
                'terms': contract.get('terms', ''),
                'hours_spent': contract.get('hours_spent', 0),
                'skill_hours_exchange': contract.get('skill_hours_exchange', 0),
                'sender_confirmed_finish': contract.get('sender_confirmed_finish', False),
                'receiver_confirmed_finish': contract.get('receiver_confirmed_finish', False),
                'completed_at': contract.get('completed_at', None),
                'sender_feedback': contract.get('sender_feedback', None),
                'receiver_feedback': contract.get('receiver_feedback', None),
                'escrow': contract.get('escrow', {
                    'sender_payment': None,
                    'receiver_payment': None
                })
            }
            contract_list.append(contract_data)

        return jsonify({'contracts': contract_list})
    except Exception as e:
        logger.error(f"Error fetching contracts: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/shutdown', methods=['POST'])
def shutdown():
    if not app.debug:
        return jsonify({'error': 'Shutdown is only available in debug mode'}), 403
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        return jsonify({'error': 'Not running with the Werkzeug Server'}), 500
    func()
    logger.info("Server shutting down...")
    return jsonify({'message': 'Server shutting down...'}), 200

def validate_payment_method(data):
    required_fields = ['card_type', 'card_number', 'expiry_date']
    for field in required_fields:
        if field not in data or not data[field]:
            return f'Missing or empty field: {field}'
    
    # Validate card number (basic check for 16 digits or last 4)
    if not re.match(r'^\d{4}$', data['card_number']) and not re.match(r'^\d{16}$', data['card_number']):
        return 'Card number must be 16 digits or last 4 digits'
    
    # Validate card type
    if data['card_type'].lower() not in ['visa', 'mastercard', 'amex']:
        return 'Card type must be Visa, Mastercard, or Amex'
    
    # Validate expiry date (MM/YYYY)
    if not re.match(r'^(0[1-9]|1[0-2])\/20[2-9][0-9]$', data['expiry_date']):
        return 'Expiry date must be MM/YYYY format and in the future'
    
    # Check if expiry date is in the future
    try:
        expiry = datetime.strptime(data['expiry_date'], '%m/%Y')
        if expiry < datetime.now():
            return 'Expiry date must be in the future'
    except ValueError:
        return 'Invalid expiry date format'
    
    return None

# Get all payment methods
@app.route('/api/payment_methods', methods=['GET'])
def get_payment_methods():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session.get('user_id')
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        payment_methods = user.get('payment_methods', [])
        return jsonify(payment_methods)
    except Exception as e:
        logger.error(f"Error fetching payment methods: {e}")
        return jsonify({'error': str(e)}), 500

# Add a payment method
@app.route('/api/payment_methods', methods=['POST'])
def add_payment_method():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    if error := validate_payment_method(data):
        return jsonify({'error': error}), 400
    user_id = session.get('user_id')
    try:
        # In a real app, you'd tokenize the card number via a payment processor
        # Here, we store only the last 4 digits
        last_four = data['card_number'][-4:] if len(data['card_number']) > 4 else data['card_number']
        payment_method = {
            'id': str(ObjectId()),  # Unique ID for the payment method
            'card_type': data['card_type'].lower(),
            'last_four': last_four,
            'expiry_date': data['expiry_date']
        }
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$push': {'payment_methods': payment_method}},
            upsert=True
        )
        logger.info(f"Payment method added for user {user_id}")
        return jsonify({'message': 'Payment method added successfully', 'payment_method': payment_method})
    except Exception as e:
        logger.error(f"Error adding payment method: {e}")
        return jsonify({'error': str(e)}), 500

# Edit a payment method
@app.route('/api/payment_methods/<payment_method_id>', methods=['PUT'])
def edit_payment_method(payment_method_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    if error := validate_payment_method(data):
        return jsonify({'error': error}), 400
    user_id = session.get('user_id')
    try:
        last_four = data['card_number'][-4:] if len(data['card_number']) > 4 else data['card_number']
        updated_method = {
            'id': payment_method_id,
            'card_type': data['card_type'].lower(),
            'last_four': last_four,
            'expiry_date': data['expiry_date']
        }
        result = users_collection.update_one(
            {'_id': ObjectId(user_id), 'payment_methods.id': payment_method_id},
            {'$set': {
                'payment_methods.$': updated_method
            }}
        )
        if result.modified_count == 0:
            return jsonify({'error': 'Payment method not found'}), 404
        logger.info(f"Payment method {payment_method_id} updated for user {user_id}")
        return jsonify({'message': 'Payment method updated successfully', 'payment_method': updated_method})
    except Exception as e:
        logger.error(f"Error updating payment method: {e}")
        return jsonify({'error': str(e)}), 500

# Remove a payment method
@app.route('/api/payment_methods/<payment_method_id>', methods=['DELETE'])
def remove_payment_method(payment_method_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session.get('user_id')
    try:
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$pull': {'payment_methods': {'id': payment_method_id}}}
        )
        if result.modified_count == 0:
            return jsonify({'error': 'Payment method not found'}), 404
        logger.info(f"Payment method {payment_method_id} removed for user {user_id}")
        return jsonify({'message': 'Payment method removed successfully'})
    except Exception as e:
        logger.error(f"Error removing payment method: {e}")
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


@app.route('/api/admin/contracts', methods=['GET'])
def get_all_contracts():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        contracts = list(contracts_collection.find())
        contract_list = []
        for contract in contracts:
            sender = users_collection.find_one({'_id': ObjectId(contract['sender_id'])})
            receiver = users_collection.find_one({'_id': ObjectId(contract['receiver_id'])})
            contract_list.append({
                'contract_id': str(contract['_id']),
                'sender_id': contract['sender_id'],
                'receiver_id': contract['receiver_id'],
                'sender_name': sender['full_name'] if sender else 'Unknown',
                'receiver_name': receiver['full_name'] if receiver else 'Unknown',
                'sender_skill_offered': contract.get('sender_skill_offered', 'Unknown'),
                'receiver_skill_offered': contract.get('receiver_skill_offered', 'Unknown'),
                'total_sessions': contract.get('total_sessions', 0),
                'sender_sessions_completed': contract.get('sender_sessions_completed', 0),
                'receiver_sessions_completed': contract.get('receiver_sessions_completed', 0),
                'status': contract.get('status', 'pending'),
                'escrow': contract.get('escrow', {'sender_payment': None, 'receiver_payment': None})
            })
        return jsonify(contract_list)
    except Exception as e:
        logger.error(f"Error fetching contracts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/payments', methods=['GET'])
def get_all_payments():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        payments = list(payments_collection.find())
        payment_list = []
        for payment in payments:
            user = users_collection.find_one({'_id': ObjectId(payment['user_id'])})
            payment_list.append({
                'payment_id': str(payment['_id']),
                'user_id': payment['user_id'],
                'user_name': user['full_name'] if user else 'Unknown',
                'contract_id': payment['contract_id'],
                'type': payment['type'],
                'amount': payment['amount'],
                'status': payment['status'],
                'created_at': payment['created_at'].isoformat()
            })
        return jsonify(payment_list)
    except Exception as e:
        logger.error(f"Error fetching payments: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/feedback', methods=['GET'])
def get_all_feedback():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    try:
        feedback = list(feedback_collection.find())
        feedback_list = []
        for item in feedback:
            user = users_collection.find_one({'_id': ObjectId(item['user_id'])})
            feedback_list.append({
                'user_id': item['user_id'],
                'user_name': user['full_name'] if user else 'Unknown',
                'feedback': item['feedback'],
                'created_at': item['created_at'].isoformat()
            })
        return jsonify(feedback_list)
    except Exception as e:
        logger.error(f"Error fetching feedback: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/update_role', methods=['POST'])
def update_user_role():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    required_fields = ['user_id', 'role']
    if error := validate_user_input(data, required_fields):
        return jsonify({'error': error}), 400
    if data['role'] not in ['user', 'superadmin']:
        return jsonify({'error': 'Invalid role'}), 400
    try:
        result = users_collection.update_one(
            {'_id': ObjectId(data['user_id'])},
            {'$set': {'role': data['role']}}
        )
        if result.matched_count == 0:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'message': 'User role updated successfully'})
    except Exception as e:
        logger.error(f"Error updating user role: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/update_platform_settings', methods=['POST'])
def update_platform_settings():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    admin = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin or admin.get('role') != 'superadmin':
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    required_fields = ['platform_fee', 'ad_expiration_days']
    if error := validate_user_input(data, required_fields):
        return jsonify({'error': error}), 400
    try:
        # In a real app, store settings in a dedicated collection
        # For simplicity, we'll assume a settings document
        db['Settings'].update_one(
            {'_id': 'platform_settings'},
            {'$set': {
                'platform_fee': float(data['platform_fee']),
                'ad_expiration_days': int(data['ad_expiration_days'])
            }},
            upsert=True
        )
        return jsonify({'message': 'Platform settings updated successfully'})
    except Exception as e:
        logger.error(f"Error updating platform settings: {e}")
        return jsonify({'error': str(e)}), 500
    

# Recent ads endpoint for the dashboard
@app.route('/api/recent_ads', methods=['GET'])
def get_recent_ads():
    try:
        ads = list(ads_collection.find({
            'status': 'active',
            'expires_at': {'$gt': datetime.utcnow()}
        }).sort('created_at', -1).limit(10))

        return jsonify([{
            'id': str(ad['_id']),
            'title': ad['title'],
            'description': ad['description'],
            'user_id': ad['user_id'],
            'user_name': ad.get('user_name', 'Unknown'),
            'image': ad.get('image', ''),
            'video': ad.get('video', ''),
            'created_at': ad['created_at'].isoformat(),
            'expires_at': ad['expires_at'].isoformat()
        } for ad in ads])

    except Exception as e:
        logger.error(f"Error fetching recent ads: {e}")
        return jsonify({'error': str(e)}), 500


# Featured Skill Swaps endpoint for the dashboard
@app.route('/api/featured_skill_swaps', methods=['GET'])
def get_featured_skill_swaps():
    try:
        contracts = list(contracts_collection.find({
            'status': 'completed'
        }).sort('completed_at', -1).limit(10))

        featured_swaps = []
        for contract in contracts:
            sender = users_collection.find_one({'_id': ObjectId(contract['sender_id'])})
            receiver = users_collection.find_one({'_id': ObjectId(contract['receiver_id'])})
            featured_swaps.append({
                'contract_id': str(contract['_id']),
                'sender_name': sender['full_name'] if sender else 'Unknown',
                'receiver_name': receiver['full_name'] if receiver else 'Unknown',
                'sender_skill_offered': contract.get('sender_skill_offered', 'Unknown'),
                'receiver_skill_offered': contract.get('receiver_skill_offered', 'Unknown'),
                'completed_at': contract['completed_at'].isoformat(),
                'sender_profile_picture': sender.get('profile_picture', ''),
                'receiver_profile_picture': receiver.get('profile_picture', '')
            })

        return jsonify(featured_swaps)

    except Exception as e:
        logger.error(f"Error fetching featured skill swaps: {e}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    default_port = int(os.getenv('PORT', 5000))
    try:
        port = find_available_port(start_port=default_port)
    except Exception as e:
        logger.error(f"Failed to find an available port: {e}")
        exit(1)

    allowed_origins = [f"http://127.0.0.1:{port}", f"http://localhost:{port}"]
    CORS(app, supports_credentials=True, resources={
        r"/uploads/*": {"origins": allowed_origins},
        r"/api/*": {"origins": allowed_origins}
    })
    socketio.init_app(app, cors_allowed_origins=allowed_origins)

    print(f"Server is running at http://localhost:{port}/ - Click to open: http://localhost:{port}/")
    socketio.run(app, host='0.0.0.0', port=port, debug=True)