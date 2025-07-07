import os
import sys
from datetime import datetime, timedelta
import bcrypt
from cryptography.fernet import Fernet
import base64
import re
from bson import ObjectId

from flask import Flask, send_from_directory, jsonify, request, Blueprint, current_app
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_cors import CORS
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy

# Load environment variables
load_dotenv()

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), \'static\'))

# Configuration
app.config[\'SECRET_KEY\'] = os.getenv(\'JWT_SECRET\', \'your-super-secret-jwt-key-change-this-in-production\')
app.config[\'JWT_SECRET_KEY\'] = os.getenv(\'JWT_SECRET\', \'your-super-secret-jwt-key-change-this-in-production\')
app.config[\'MONGO_URI\'] = os.getenv(\'MONGODB_URI\', \'mongodb://localhost:27017/secret-method-hub\')

# Initialize extensions
mongo = PyMongo(app)
jwt = JWTManager(app)
CORS(app, origins=\"*\", supports_credentials=True)

# Store mongo instance in app for access in routes
app.mongo = mongo

# Keep SQLAlchemy for compatibility but we\'ll use MongoDB
db = SQLAlchemy()
app.config[\'SQLALCHEMY_DATABASE_URI\'] = f\"sqlite:///{os.path.join(os.path.dirname(__file__), \'database\', \'app.db\')}\"
app.config[\'SQLALCHEMY_TRACK_MODIFICATIONS\'] = False
db.init_app(app)
with app.app_context():
    db.create_all()

class UserModel:
    def __init__(self, mongo):
        self.mongo = mongo
        self.collection = mongo.db.users
    
    def create_user(self, email, password, first_name, last_name):
        \"\"\"Create a new user with encrypted key\"\"\"
        if self.collection.find_one({\"email\": email}):
            return None
        
        password_hash = bcrypt.hashpw(password.encode(\'utf-8\'), bcrypt.gensalt())
        encrypted_key = self._generate_encrypted_key(email)
        
        user_data = {
            \"email\": email,
            \"password\": password_hash,
            \"firstName\": first_name,
            \"lastName\": last_name,
            \"encryptedKey\": encrypted_key,
            \"isApproved\": False,
            \"isAdmin\": False,
            \"approvedAt\": None,
            \"approvedBy\": None,
            \"rejectedAt\": None,
            \"rejectedBy\": None,
            \"rejectionReason\": None,
            \"createdAt\": datetime.utcnow(),
            \"updatedAt\": datetime.utcnow()
        }
        
        result = self.collection.insert_one(user_data)
        user_data[\'_id\'] = result.inserted_id
        return user_data
    
    def find_by_email(self, email):
        \"\"\"Find user by email\"\"\"
        return self.collection.find_one({\"email\": email})
    
    def find_by_id(self, user_id):
        \"\"\"Find user by ID\"\"\"
        return self.collection.find_one({\"_id\": ObjectId(user_id)})
    
    def verify_password(self, user, password):
        \"\"\"Verify user password\"\"\"
        return bcrypt.checkpw(password.encode(\'utf-8\'), user[\'password\'])
    
    def approve_user(self, user_id, admin_id):
        \"\"\"Approve a user\"\"\"
        result = self.collection.update_one(
            {\"_id\": ObjectId(user_id)},
            {
                \"$set\": {
                    \"isApproved\": True,
                    \"approvedAt\": datetime.utcnow(),
                    \"approvedBy\": ObjectId(admin_id),
                    \"rejectedAt\": None,
                    \"rejectedBy\": None,
                    \"rejectionReason\": None,
                    \"updatedAt\": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
    
    def reject_user(self, user_id, admin_id, reason=None):
        \"\"\"Reject a user\"\"\"
        result = self.collection.update_one(
            {\"_id\": ObjectId(user_id)},
            {
                \"$set\": {
                    \"isApproved\": False,
                    \"rejectedAt\": datetime.utcnow(),
                    \"rejectedBy\": ObjectId(admin_id),
                    \"rejectionReason\": reason,
                    \"approvedAt\": None,
                    \"approvedBy\": None,
                    \"updatedAt\": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
    
    def get_users_by_status(self, status=\"all\", page=1, limit=10):
        \"\"\"Get users filtered by status\"\"\"
        filter_query = {\"isAdmin\": False}
        
        if status == \"pending\":
            filter_query.update({\"isApproved\": False, \"rejectedAt\": None})
        elif status == \"approved\":
            filter_query.update({\"isApproved\": True})
        elif status == \"rejected\":
            filter_query.update({\"rejectedAt\": {\"$ne\": None}})
        
        skip = (page - 1) * limit
        users = list(self.collection.find(filter_query).sort(\"createdAt\", -1).skip(skip).limit(limit))
        total = self.collection.count_documents(filter_query)
        
        return users, total
    
    def get_user_stats(self):
        \"\"\"Get user statistics\"\"\"
        total_users = self.collection.count_documents({\"isAdmin\": False})
        approved_users = self.collection.count_documents({\"isApproved\": True, \"isAdmin\": False})
        pending_users = self.collection.count_documents({
            \"isApproved\": False, 
            \"rejectedAt\": None, 
            \"isAdmin\": False
        })
        rejected_users = self.collection.count_documents({
            \"rejectedAt\": {\"$ne\": None}, 
            \"isAdmin\": False
        })
        
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        recent_registrations = self.collection.count_documents({
            \"createdAt\": {\"$gte\": seven_days_ago},
            \"isAdmin\": False
        })
        
        return {
            \"totalUsers\": total_users,
            \"approvedUsers\": approved_users,
            \"pendingUsers\": pending_users,
            \"rejectedUsers\": rejected_users,
            \"recentRegistrations\": recent_registrations,
            \"approvalRate\": round((approved_users / total_users * 100), 1) if total_users > 0 else 0
        }
    
    def create_admin_user(self, email, password, first_name=\"Admin\", last_name=\"User\"):
        \"\"\"Create admin user\"\"\"
        if self.collection.find_one({\"email\": email}):
            return self.collection.find_one({\"email\": email})
        
        password_hash = bcrypt.hashpw(password.encode(\'utf-8\'), bcrypt.gensalt())
        encrypted_key = self._generate_encrypted_key(email)
        
        admin_data = {
            \"email\": email,
            \"password\": password_hash,
            \"firstName\": first_name,
            \"lastName\": last_name,
            \"encryptedKey\": encrypted_key,
            \"isApproved\": True,
            \"isAdmin\": True,
            \"approvedAt\": datetime.utcnow(),
            \"approvedBy\": None,
            \"rejectedAt\": None,
            \"rejectedBy\": None,
            \"rejectionReason\": None,
            \"createdAt\": datetime.utcnow(),
            \"updatedAt\": datetime.utcnow()
        }
        
        result = self.collection.insert_one(admin_data)
        admin_data[\'_id\'] = result.inserted_id
        return admin_data
    
    def _generate_encrypted_key(self, email):
        \"\"\"Generate encrypted key for user\"\"\"
        unique_string = f\"{email}-{datetime.utcnow().timestamp()}\"
        encryption_key = os.getenv(\'ENCRYPTION_KEY\', \'default-key-change-this-in-production-32chars\')
        key = base64.urlsafe_b64encode(encryption_key.encode()[:32].ljust(32, b\'0\'))
        fernet = Fernet(key)
        encrypted = fernet.encrypt(unique_string.encode())
        return encrypted.decode()
    
    def decrypt_user_key(self, encrypted_key):
        \"\"\"Decrypt user key\"\"\"
        try:
            encryption_key = os.getenv(\'ENCRYPTION_KEY\', \'default-key-change-this-in-production-32chars\')
            key = base64.urlsafe_b64encode(encryption_key.encode()[:32].ljust(32, b\'0\'))
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted_key.encode())
            return decrypted.decode()
        except Exception:
            return None
    
    def update_user_profile(self, user_id, first_name, last_name):
        \"\"\"Update user profile\"\"\"
        result = self.collection.update_one(
            {\"_id\": ObjectId(user_id)},
            {
                \"$set\": {
                    \"firstName\": first_name,
                    \"lastName\": last_name,
                    \"updatedAt\": datetime.utcnow()
                }
            }
        )
        return result.modified_count > 0
    
    def delete_user(self, user_id):
        \"\"\"Delete user account\"\"\"
        result = self.collection.delete_one({\"_id\": ObjectId(user_id), \"isAdmin\": False})
        return result.deleted_count > 0

# Blueprints
auth_bp = Blueprint(\'auth\', __name__)
admin_bp = Blueprint(\'admin\', __name__)
user_bp = Blueprint(\'user\', __name__)

def get_user_model():
    \"\"\"Get user model instance\"\"\"
    return UserModel(current_app.mongo)

def require_admin():
    \"\"\"Decorator to require admin access\"\"\"
    def decorator(f):
        def wrapper(*args, **kwargs):
            try:
                user_id = get_jwt_identity()
                claims = get_jwt()
                
                if not claims.get(\'isAdmin\'):
                    return jsonify({\'message\': \'Admin access required\'}), 403
                
                user_model = get_user_model()
                user = user_model.find_by_id(user_id)
                
                if not user or not user[\'isAdmin\'] or not user[\'isApproved\']:
                    return jsonify({\'message\': \'Admin access required\'}), 403
                
                return f(*args, **kwargs)
            except Exception as e:
                return jsonify({\'message\': \'Authentication failed\', \'error\': str(e)}), 500
        
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# Auth Routes
@auth_bp.route(\'/register\', methods=[\'POST\'])
def register():
    try:
        data = request.get_json()
        required_fields = [\'email\', \'password\', \'firstName\', \'lastName\']
        for field in required_fields:
            if not data.get(field):
                return jsonify({\'message\': \'All fields are required\', \'required\': required_fields}), 400
        
        email = data[\'email\'].lower().strip()
        password = data[\'password\']
        first_name = data[\'firstName\'].strip()
        last_name = data[\'lastName\'].strip()
        
        if not re.match(r\'^[\\s@]+@[\\s@]+\\.[\\s@]+$\\', email):
            return jsonify({\'message\': \'Invalid email format\'}), 400
        
        if len(password) < 6:
            return jsonify({\'message\': \'Password must be at least 6 characters\'}), 400
        
        user_model = get_user_model()
        user = user_model.create_user(email, password, first_name, last_name)
        if not user:
            return jsonify({\'message\': \'User already exists with this email\'}), 409
        
        access_token = create_access_token(
            identity=str(user[\'_id\']),
            additional_claims={\'email\': user[\'email\'], \'isAdmin\': user[\'isAdmin\']}
        )
        
        return jsonify({
            \'message\': \'User registered successfully\',
            \'token\': access_token,
            \'user\': {
                \'id\': str(user[\'_id\']),
                \'email\': user[\'email\'],
                \'firstName\': user[\'firstName\'],
                \'lastName\': user[\'lastName\'],
                \'isApproved\': user[\'isApproved\'],
                \'isAdmin\': user[\'isAdmin\']
            }
        }), 201
        
    except Exception as e:
        return jsonify({\'message\': \'Registration failed\', \'error\': str(e)}), 500

@auth_bp.route(\'/login\', methods=[\'POST\'])
def login():
    try:
        data = request.get_json()
        if not data.get(\'email\') or not data.get(\'password\'):
            return jsonify({\'message\': \'Email and password are required\'}), 400
        
        email = data[\'email\'].lower().strip()
        password = data[\'password\']
        
        user_model = get_user_model()
        user = user_model.find_by_email(email)
        if not user:
            return jsonify({\'message\': \'Invalid email or password\'}), 401
        
        if not user_model.verify_password(user, password):
            return jsonify({\'message\': \'Invalid email or password\'}), 401
        
        access_token = create_access_token(
            identity=str(user[\'_id\']),
            additional_claims={\'email\': user[\'email\'], \'isAdmin\': user[\'isAdmin\']}
        )
        
        return jsonify({
            \'message\': \'Login successful\',
            \'token\': access_token,
            \'user\': {
                \'id\': str(user[\'_id\']),
                \'email\': user[\'email\'],
                \'firstName\': user[\'firstName\'],
                \'lastName\': user[\'lastName\'],
                \'isApproved\': user[\'isApproved\'],
                \'isAdmin\': user[\'isAdmin\']
            }
        })
        
    except Exception as e:
        return jsonify({\'message\': \'Login failed\', \'error\': str(e)}), 500

@auth_bp.route(\'/profile\', methods=[\'GET\'])
@jwt_required()
def get_profile():
    try:
        user_id = get_jwt_identity()
        user_model = get_user_model()
        user = user_model.find_by_id(user_id)
        if not user:
            return jsonify({\'message\': \'User not found\'}), 404
        
        return jsonify({
            \'user\': {
                \'id\': str(user[\'_id\']),
                \'email\': user[\'email\'],
                \'firstName\': user[\'firstName\'],
                \'lastName\': user[\'lastName\'],
                \'isApproved\': user[\'isApproved\'],
                \'isAdmin\': user[\'isAdmin\'],
                \'createdAt\': user[\'createdAt\'].isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({\'message\': \'Failed to get profile\', \'error\': str(e)}), 500

@auth_bp.route(\'/secret-key\', methods=[\'GET\'])
@jwt_required()
def get_secret_key():
    try:
        user_id = get_jwt_identity()
        user_model = get_user_model()
        user = user_model.find_by_id(user_id)
        if not user:
            return jsonify({\'message\': \'User not found\'}), 404
        
        if not user[\'isApproved\']:
            return jsonify({\'message\': \'Account pending approval\', \'isApproved\': False}), 403
        
        decrypted_key = user_model.decrypt_user_key(user[\'encryptedKey\'])
        
        return jsonify({
            \'message\': \'Secret key retrieved successfully\',
            \'secretKey\': decrypted_key,
            \'user\': {
                \'id\': str(user[\'_id\']),
                \'email\': user[\'email\'],
                \'firstName\': user[\'firstName\'],
                \'lastName\': user[\'lastName\']
            }
        })
        
    except Exception as e:
        return jsonify({\'message\': \'Failed to retrieve secret key\', \'error\': str(e)}), 500

@auth_bp.route(\'/verify\', methods=[\'POST\'])
@jwt_required()
def verify_token():
    try:
        user_id = get_jwt_identity()
        user_model = get_user_model()
        user = user_model.find_by_id(user_id)
        if not user:
            return jsonify({\'message\': \'User not found\'}), 404
        
        return jsonify({
            \'message\': \'Token is valid\',
            \'user\': {
                \'id\': str(user[\'_id\']),
                \'email\': user[\'email\'],
                \'firstName\': user[\'firstName\'],
                \'lastName\': user[\'lastName\'],
                \'isApproved\': user[\'isApproved\'],
                \'isAdmin\': user[\'isAdmin\']
            }
        })
        
    except Exception as e:
        return jsonify({\'message\': \'Token verification failed\', \'error\': str(e)}), 500

# Admin Routes
@admin_bp.route(\'/users\', methods=[\'GET\'])
@jwt_required()
@require_admin()
def get_users():
    try:
        page = int(request.args.get(\'page\', 1))
        limit = int(request.args.get(\'limit\', 10))
        status = request.args.get(\'status\', \'all\')
        
        user_model = get_user_model()
        users, total = user_model.get_users_by_status(status, page, limit)
        
        formatted_users = []
        for user in users:
            formatted_user = {
                \'_id\': str(user[\'_id\']),
                \'email\': user[\'email\'],
                \'firstName\': user[\'firstName\'],
                \'lastName\': user[\'lastName\'],
                \'isApproved\': user[\'isApproved\'],
                \'isAdmin\': user[\'isAdmin\'],
                \'createdAt\': user[\'createdAt\'].isoformat(),
                \'updatedAt\': user[\'updatedAt\'].isoformat(),
                \'approvedAt\': user[\'approvedAt\'].isoformat() if user[\'approvedAt\'] else None,
                \'rejectedAt\': user[\'rejectedAt\'].isoformat() if user[\'rejectedAt\'] else None,
                \'rejectionReason\': user.get(\'rejectionReason\'),
                \'approvedBy\': str(user[\'approvedBy\']) if user.get(\'approvedBy\') else None,
                \'rejectedBy\': str(user[\'rejectedBy\']) if user.get(\'rejectedBy\') else None
            }
            formatted_users.append(formatted_user)
        
        return jsonify({
            \'users\': formatted_users,
            \'pagination\': {
                \'currentPage\': page,
                \'totalPages\': (total + limit - 1) // limit,
                \'totalUsers\': total,
                \'hasNext\': page * limit < total,
                \'hasPrev\': page > 1
            }
        })
        
    except Exception as e:
        return jsonify({\'message\': \'Failed to retrieve users\', \'error\': str(e)}), 500

@admin_bp.route(\'/stats\', methods=[\'GET\'])
@jwt_required()
@require_admin()
def get_stats():
    try:
        user_model = get_user_model()
        stats = user_model.get_user_stats()
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({\'message\': \'Failed to retrieve statistics\', \'error\': str(e)}), 500

@admin_bp.route(\'/approve/<user_id>\', methods=[\'POST\'])
@jwt_required()
@require_admin()
def approve_user(user_id):
    try:
        admin_id = get_jwt_identity()
        user_model = get_user_model()
        user = user_model.find_by_id(user_id)
        if not user:
            return jsonify({\'message\': \'User not found\'}), 404
        
        if user[\'isAdmin\']:
            return jsonify({\'message\': \'Cannot modify admin user\'}), 400
        
        if user[\'isApproved\']:
            return jsonify({\'message\': \'User is already approved\'}), 400
        
        success = user_model.approve_user(user_id, admin_id)
        if not success:
            return jsonify({\'message\': \'Failed to approve user\'}), 500
        
        updated_user = user_model.find_by_id(user_id)
        
        return jsonify({
            \'message\': \'User approved successfully\',
            \'user\': {
                \'id\': str(updated_user[\'_id\']),
                \'email\': updated_user[\'email\'],
                \'firstName\': updated_user[\'firstName\'],
                \'lastName\': updated_user[\'lastName\'],
                \'isApproved\': updated_user[\'isApproved\'],
                \'approvedAt\': updated_user[\'approvedAt\'].isoformat() if updated_user[\'approvedAt\'] else None
            }
        })
        
    except Exception as e:
        return jsonify({\'message\': \'Failed to approve user\', \'error\': str(e)}), 500

@admin_bp.route(\'/reject/<user_id>\', methods=[\'POST\'])
@jwt_required()
@require_admin()
def reject_user(user_id):
    try:
        admin_id = get_jwt_identity()
        data = request.get_json() or {}
        reason = data.get(\'reason\')
        
        user_model = get_user_model()
        user = user_model.find_by_id(user_id)
        if not user:
            return jsonify({\'message\': \'User not found\'}), 404
        
        if user[\'isAdmin\']:
            return jsonify({\'message\': \'Cannot modify admin user\'}), 400
        
        success = user_model.reject_user(user_id, admin_id, reason)
        if not success:
            return jsonify({\'message\': \'Failed to reject user\'}), 500
        
        updated_user = user_model.find_by_id(user_id)
        
        return jsonify({
            \'message\': \'User rejected successfully\',
            \'user\': {
                \'id\': str(updated_user[\'_id\']),
                \'email\': updated_user[\'email\'],
                \'firstName\': updated_user[\'firstName\'],
                \'lastName\': updated_user[\'lastName\'],
                \'isApproved\': updated_user[\'isApproved\'],
                \'rejectedAt\': updated_user[\'rejectedAt\'].isoformat() if updated_user[\'rejectedAt\'] else None,
                \'rejectionReason\': updated_user.get(\'rejectionReason\')
            }
        })
        
    except Exception as e:
        return jsonify({\'message\': \'Failed to reject user\', \'error\': str(e)}), 500

@admin_bp.route(\'/user/<user_id>\', methods=[\'GET\'])
@jwt_required()
@require_admin()
def get_user_details(user_id):
    try:
        user_model = get_user_model()
        user = user_model.find_by_id(user_id)
        if not user:
            return jsonify({\'message\': \'User not found\'}), 404
        
        formatted_user = {
            \'_id\': str(user[\'_id\']),
            \'email\': user[\'email\'],
            \'firstName\': user[\'firstName\'],
            \'lastName\': user[\'lastName\'],
            \'isApproved\': user[\'isApproved\'],
            \'isAdmin\': user[\'isAdmin\'],
            \'createdAt\': user[\'createdAt\'].isoformat(),
            \'updatedAt\': user[\'updatedAt\'].isoformat(),
            \'approvedAt\': user[\'approvedAt\'].isoformat() if user[\'approvedAt\'] else None,
            \'rejectedAt\': user[\'rejectedAt\'].isoformat() if user[\'rejectedAt\'] else None,
            \'rejectionReason\': user.get(\'rejectionReason\'),
            \'approvedBy\': str(user[\'approvedBy\']) if user.get(\'approvedBy\') else None,
            \'rejectedBy\': str(user[\'rejectedBy\']) if user.get(\'rejectedBy\') else None
        }
        
        return jsonify({\'user\': formatted_user})
        
    except Exception as e:
        return jsonify({\'message\': \'Failed to retrieve user details\', \'error\': str(e)}), 500

@admin_bp.route(\'/bulk-approve\', methods=[\'POST\'])
@jwt_required()
@require_admin()
def bulk_approve():
    try:
        admin_id = get_jwt_identity()
        data = request.get_json()
        user_ids = data.get(\'userIds\', [])
        if not isinstance(user_ids, list) or len(user_ids) == 0:
            return jsonify({\'message\': \'User IDs array is required\'}), 400
        
        user_model = get_user_model()
        approved_users = []
        
        for user_id in user_ids:
            try:
                user = user_model.find_by_id(user_id)
                if user and not user[\'isAdmin\'] and not user[\'isApproved\']:
                    success = user_model.approve_user(user_id, admin_id)
                    if success:
                        approved_users.append({
                            \'id\': str(user[\'_id\']),
                            \'email\': user[\'email\'],
                            \'firstName\': user[\'firstName\'],
                            \'lastName\': user[\'lastName\']
                        })
            except Exception:
                continue
        
        return jsonify({\'message\': f\'{len(approved_users)} users approved successfully\', \'approvedUsers\': approved_users})
        
    except Exception as e:
        return jsonify({\'message\': \'Failed to approve users\', \'error\': str(e)}), 500

# User Routes
@user_bp.route(\'/status\', methods=[\'GET\'])
@jwt_required()
def get_user_status():
    try:
        user_id = get_jwt_identity()
        user_model = get_user_model()
        user = user_model.find_by_id(user_id)
        if not user:
            return jsonify({\'message\': \'User not found\'}), 404
        
        return jsonify({
            \'user\': {
                \'id\': str(user[\'_id\']),
                \'email\': user[\'email\'],
                \'firstName\': user[\'firstName\'],
                \'lastName\': user[\'lastName\'],
                \'isApproved\': user[\'isApproved\'],
                \'isAdmin\': user[\'isAdmin\'],
                \'approvedAt\': user[\'approvedAt\'].isoformat() if user[\'approvedAt\'] else None,
                \'rejectedAt\': user[\'rejectedAt\'].isoformat() if user[\'rejectedAt\'] else None,
                \'rejectionReason\': user.get(\'rejectionReason\'),
                \'createdAt\': user[\'createdAt\'].isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({\'message\': \'Failed to get user status\', \'error\': str(e)}), 500

@user_bp.route(\'/secret-content\', methods=[\'GET\'])
@jwt_required()
def get_secret_content():
    try:
        user_id = get_jwt_identity()
        user_model = get_user_model()
        user = user_model.find_by_id(user_id)
        if not user:
            return jsonify({\'message\': \'User not found\'}), 404
        
        if not user[\'isApproved\']:
            return jsonify({\'message\': \'Account pending approval\', \'isApproved\': False}), 403
        
        secret_content = {
            \"message\": \"Congratulations! You have been approved and can now access the secret content.\",
            \"links\": [
                {\"title\": \"Secret Method #1: Advanced Techniques\", \"url\": \"https://example.com/secret-method-1\", \"description\": \"Learn the first secret method that will transform your approach.\"},
                {\"title\": \"Secret Method #2: Hidden Strategies\", \"url\": \"https://example.com/secret-method-2\", \"description\": \"Discover the hidden strategies used by experts.\"},
                {\"title\": \"Exclusive Video Content\", \"url\": \"https://example.com/exclusive-videos\", \"description\": \"Access to exclusive video tutorials and masterclasses.\"}
            ],
            \"videos\": [
                {\"title\": \"Master Class: Secret Techniques Revealed\", \"embedUrl\": \"https://www.youtube.com/embed/dQw4w9WgXcQ\", \"description\": \"A comprehensive masterclass revealing all secret techniques.\"},
                {\"title\": \"Advanced Training Session\", \"embedUrl\": \"https://www.youtube.com/embed/dQw4w9WgXcQ\", \"description\": \"Advanced training for implementing the secret methods.\"}
            ],
            \"documents\": [
                {\"title\": \"Secret Method Handbook\", \"downloadUrl\": \"https://example.com/handbook.pdf\", \"description\": \"Complete handbook with all secret methods documented.\"},
                {\"title\": \"Implementation Guide\", \"downloadUrl\": \"https://example.com/guide.pdf\", \"description\": \"Step-by-step implementation guide.\"}
            ],
            \"lastUpdated\": datetime.utcnow( ).isoformat()
        }
        
        user_key = user_model.decrypt_user_key(user[\'encryptedKey\'])
        
        return jsonify({\'message\': \'Secret content retrieved successfully\', \'content\': secret_content, \'userKey\': user_key})
        
    except Exception as e:
        return jsonify({\'message\': \'Failed to retrieve secret content\', \'error\': str(e)}), 500

@user_bp.route(\'/profile\', methods=[\'PUT\'])
@jwt_required()
def update_profile():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        first_name = data.get(\'firstName\', \'\').strip()
        last_name = data.get(\'lastName\', \'\').strip()
        
        if not first_name or not last_name:
            return jsonify({\'message\': \'First name and last name are required\'}), 400
        
        user_model = get_user_model()
        success = user_model.update_user_profile(user_id, first_name, last_name)
        if not success:
            return jsonify({\'message\': \'Failed to update profile\'}), 500
        
        user = user_model.find_by_id(user_id)
        
        return jsonify({
            \'message\': \'Profile updated successfully\',
            \'user\': {
                \'id\': str(user[\'_id\']),
                \'email\': user[\'email\'],
                \'firstName\': user[\'firstName\'],
                \'lastName\': user[\'lastName\'],
                \'isApproved\': user[\'isApproved\'],
                \'isAdmin\': user[\'isAdmin\']
            }
        })
        
    except Exception as e:
        return jsonify({\'message\': \'Failed to update profile\', \'error\': str(e)}), 500

@user_bp.route(\'/account\', methods=[\'DELETE\'])
@jwt_required()
def delete_account():
    try:
        user_id = get_jwt_identity()
        user_model = get_user_model()
        user = user_model.find_by_id(user_id)
        if user and user[\'isAdmin\']:
            return jsonify({\'message\': \'Admin accounts cannot be deleted\'}), 400
        
        success = user_model.delete_user(user_id)
        if not success:
            return jsonify({\'message\': \'Failed to delete account\'}), 500
        
        return jsonify({\'message\': \'Account deleted successfully\'}) 
    except Exception as e:
        return jsonify({\'message\': \'Failed to delete account\', \'error\': str(e)}), 500

# Register blueprints
app.register_blueprint(auth_bp, url_prefix=\'/api/auth\')
app.register_blueprint(admin_bp, url_prefix=\'/api/admin\')
app.register_blueprint(user_bp, url_prefix=\'/api/users\')

# API root endpoint
@app.route(\'/api\')
def api_root():
    return jsonify({
        \'message\': \'Secret Method Hub API is running!\',
        \'version\': \'1.0.0\',
        \'endpoints\': {
            \'auth\': \'/api/auth\',
            \'admin\': \'/api/admin\',
            \'users\': \'/api/users\'
        }
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({\'message\': \'Route not found\'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({\'message\': \'Internal server error\'}), 500

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({\'message\': \'Unauthorized access\'}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({\'message\': \'Forbidden access\'}), 403

# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({\'message\': \'Token has expired\'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({\'message\': \'Invalid token\'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({\'message\': \'Access token required\'}), 401

# Serve static files and handle React routing
@app.route(\'/\', defaults={\'path\': \'\'}) 
@app.route(\'/<path:path>\')
def serve(path):
    static_folder_path = app.static_folder
    if static_folder_path is None:
        return \"Static folder not configured\", 404

    if path != \"\" and os.path.exists(os.path.join(static_folder_path, path)):
        return send_from_directory(static_folder_path, path)
    else:
        index_path = os.path.join(static_folder_path, \'index.html\')
        if os.path.exists(index_path):
            return send_from_directory(static_folder_path, \'index.html\')
        else:
            return \"index.html not found\", 404

# Initialize admin user on startup
def create_admin_user():
    \"\"\"Create admin user if it doesn\'t exist\"\"\"
    try:
        user_model = UserModel(mongo)
        admin_email = os.getenv(\'ADMIN_EMAIL\', \'admin@secretmethod.com\')
        admin_password = os.getenv(\'ADMIN_PASSWORD\', \'admin123\')
        
        admin_user = user_model.create_admin_user(admin_email, admin_password)
        if admin_user:
            print(f\"Admin user created/verified: {admin_email}\")
        else:
            print(\"Admin user already exists\")
    except Exception as e:
        print(f\"Error creating admin user: {e}\")

if __name__ == \'__main__\':
    with app.app_context():
        create_admin_user()
    app.run(host=\'0.0.0.0\', port=5000, debug=True)
