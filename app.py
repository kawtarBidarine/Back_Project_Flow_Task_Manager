"""
Project Management API - Optimized 2026
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_caching import Cache
import jwt
import datetime
import os
import re
import psycopg2
from psycopg2.extras import RealDictCursor, execute_batch
from psycopg2 import pool
from functools import wraps
from email_validator import validate_email, EmailNotValidError
import secrets
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


app = Flask(__name__)

# ============================================
# CONFIGURATION - Optimized for Performance
# ============================================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_EXPIRATION_HOURS'] = 24

# Caching Configuration
app.config['CACHE_TYPE'] = 'simple'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300
cache = Cache(app)

# PostgreSQL Connection Pool - CRITICAL for performance
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set!")

try:
    connection_pool = psycopg2.pool.SimpleConnectionPool(1, 20, DATABASE_URL)
    print("--- [4] Connection Pool Created Successfully ---")
except Exception as e:
    print(f"!!! DATABASE CONNECTION ERROR: {e}")
    exit(1)

# CORS
ALLOWED_ORIGINS = [
    'https://nimble-fairy-72aeaa.netlify.app',
    'http://localhost:5173', 
    'http://localhost:3000', 
]

CORS(app, 
     resources={r"/api/*": {"origins": "*"}}, 
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     supports_credentials=True,
     max_age=3600 
)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://"
)

bcrypt = Bcrypt(app)

# ============================================
# DATABASE CONNECTION POOL MANAGEMENT
# ============================================
def get_db_connection():
    """Get connection from pool"""
    return connection_pool.getconn()

def return_db_connection(conn):
    """Return connection to pool"""
    connection_pool.putconn(conn)

def execute_query(query, params=None, fetch=True, fetch_one=False):
    """Optimized query execution with connection pooling"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params or ())
            if fetch:
                return cur.fetchone() if fetch_one else cur.fetchall()
            conn.commit()
            return cur.rowcount
    finally:
        return_db_connection(conn)

# ============================================
# JWT UTILITIES
# ============================================
def generate_token(user_id, email):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=app.config['JWT_EXPIRATION_HOURS']),
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM'])

def token_required(f):
    """Token verification decorator with caching"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=[app.config['JWT_ALGORITHM']])
            
            # Cache user data to reduce DB calls
            cache_key = f"user_{data['user_id']}"
            current_user = cache.get(cache_key)
            
            if not current_user:
                current_user = execute_query(
                    "SELECT id, email, name, role FROM users WHERE id = %s",
                    (data['user_id'],),
                    fetch_one=True
                )
                if current_user:
                    cache.set(cache_key, dict(current_user), timeout=300)
            
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(dict(current_user), *args, **kwargs)
    
    return decorated

# ============================================
# AUTHENTICATION ENDPOINTS
# ============================================
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    """Register new user"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'message': 'Email and password required'}), 400
        
        # Validate email
        try:
            validate_email(email)
        except EmailNotValidError as e:
            return jsonify({'message': f'Invalid email: {str(e)}'}), 400
        
        # Check if user exists
        existing = execute_query("SELECT id FROM users WHERE email = %s", (email,), fetch_one=True)
        if existing:
            return jsonify({'message': 'User already exists'}), 409
        
        # Hash password
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user_id = secrets.token_hex(16)
        
        # Create user
        execute_query(
            "INSERT INTO users (id, email, password_hash, created_at) VALUES (%s, %s, %s, %s)",
            (user_id, email, password_hash, datetime.datetime.utcnow()),
            fetch=False
        )
        
        token = generate_token(user_id, email)
        
        return jsonify({
            'message': 'User created successfully',
            'token': token,
            'user': {'id': user_id, 'email': email}
        }), 201
        
    except Exception as e:
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("20 per minute")
def login():
    """User login"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'message': 'Email and password required'}), 400
        
        user = execute_query(
            "SELECT id, email, password_hash, name, role FROM users WHERE email = %s",
            (email,),
            fetch_one=True
        )
        
        if not user or not bcrypt.check_password_hash(user['password_hash'], password):
            bcrypt.generate_password_hash("dummy")  # Timing attack prevention
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # Update last login
        execute_query(
            "UPDATE users SET last_login = %s WHERE id = %s",
            (datetime.datetime.utcnow(), user['id']),
            fetch=False
        )
        
        token = generate_token(user['id'], user['email'])
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'name': user.get('name'),
                'role': user.get('role', 'member')
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Login failed', 'error': str(e)}), 500

# ============================================
# USER ENDPOINTS
# ============================================
@app.route('/api/user/profile', methods=['GET'])
@token_required
@cache.cached(timeout=60, query_string=True)
def get_profile(current_user):
    """Get user profile"""
    user = execute_query(
        "SELECT id, email, name, bio, avatar, role, department, created_at FROM users WHERE id = %s",
        (current_user['id'],),
        fetch_one=True
    )
    return jsonify({'user': dict(user)}), 200

@app.route('/api/user/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    """Update user profile"""
    data = request.get_json()
    allowed_fields = ['name', 'bio', 'avatar', 'department', 'phone', 'timezone']
    
    updates = {k: v for k, v in data.items() if k in allowed_fields}
    if not updates:
        return jsonify({'message': 'No valid fields to update'}), 400
    
    set_clause = ", ".join([f"{k} = %s" for k in updates.keys()])
    values = list(updates.values()) + [current_user['id']]
    
    execute_query(
        f"UPDATE users SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
        values,
        fetch=False
    )
    
    # Clear cache
    cache.delete(f"user_{current_user['id']}")
    
    return jsonify({'message': 'Profile updated'}), 200

# ============================================
# ADMIN USER MANAGEMENT ENDPOINTS
# ============================================

def admin_required(f):
    """Decorator to check if user is admin"""
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.get('role') != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def get_all_users(current_user):
    """Get all users in the system (admin only)"""
    try:
        search = request.args.get('search', '')
        role_filter = request.args.get('role', '')
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        query = """
            SELECT 
                u.id,
                u.email,
                u.name,
                u.role,
                u.department,
                u.phone,
                u.avatar,
                u.bio,
                u.created_at,
                u.last_login,
                (SELECT COUNT(DISTINCT pm.project_id) 
                 FROM project_members pm 
                 WHERE pm.user_id = u.id) as project_count,
                (SELECT COUNT(*) 
                 FROM tasks t 
                 WHERE t.assignee_id = u.id 
                 AND t.status NOT IN ('done', 'archived')) as active_tasks
            FROM users u
            WHERE 1=1
        """
        
        params = []
        
        # Search filter
        if search:
            query += " AND (LOWER(u.name) LIKE %s OR LOWER(u.email) LIKE %s)"
            search_param = f"%{search.lower()}%"
            params.extend([search_param, search_param])
        
        # Role filter
        if role_filter:
            query += " AND u.role = %s"
            params.append(role_filter)
        
        query += " ORDER BY u.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        users = execute_query(query, tuple(params))
        
        # Get total count
        count_query = "SELECT COUNT(*) as total FROM users WHERE 1=1"
        count_params = []
        
        if search:
            count_query += " AND (LOWER(name) LIKE %s OR LOWER(email) LIKE %s)"
            count_params.extend([search_param, search_param])
        
        if role_filter:
            count_query += " AND role = %s"
            count_params.append(role_filter)
        
        total_result = execute_query(count_query, tuple(count_params), fetch_one=True)
        total = total_result['total'] if total_result else 0
        
        formatted_users = []
        for user in users:
            u_dict = dict(user)
            formatted_users.append({
                'id': u_dict['id'],
                'email': u_dict['email'],
                'name': u_dict.get('name'),
                'role': u_dict.get('role', 'member'),
                'department': u_dict.get('department'),
                'phone': u_dict.get('phone'),
                'avatar': u_dict.get('avatar'),
                'bio': u_dict.get('bio'),
                'createdAt': u_dict['created_at'].isoformat() if u_dict.get('created_at') else None,
                'lastLogin': u_dict['last_login'].isoformat() if u_dict.get('last_login') else None,
                'projectCount': u_dict.get('project_count', 0),
                'activeTasks': u_dict.get('active_tasks', 0)
            })
        
        return jsonify({
            'users': formatted_users,
            'total': total,
            'limit': limit,
            'offset': offset
        }), 200
        
    except Exception as e:
        import traceback
        print(f"Error fetching users: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'message': 'Failed to fetch users', 'error': str(e)}), 500

@app.route('/api/admin/users', methods=['POST'])
@token_required
@admin_required
def create_user_admin(current_user):
    """Create new user (admin only)"""
    try:
        data = request.get_json()
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '').strip()
        role = data.get('role', 'member')
        
        if not email or not password:
            return jsonify({'message': 'Email and password required'}), 400
        
        # Validate email
        try:
            validate_email(email)
        except EmailNotValidError as e:
            return jsonify({'message': f'Invalid email: {str(e)}'}), 400
        
        # Check if user exists
        existing = execute_query(
            "SELECT id FROM users WHERE email = %s", 
            (email,), 
            fetch_one=True
        )
        
        if existing:
            return jsonify({'message': 'User already exists'}), 409
        
        # Hash password
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        user_id = secrets.token_hex(16)
        
        # Create user with additional fields
        execute_query("""
            INSERT INTO users (
                id, email, password_hash, name, role, 
                department, phone, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        """, (
            user_id,
            email,
            password_hash,
            name or None,
            role,
            data.get('department'),
            data.get('phone'),
        ), fetch=False)
        
        # Clear user cache
        cache.delete(f"user_{user_id}")
        
        return jsonify({
            'message': 'User created successfully',
            'id': user_id,
            'email': email
        }), 201
        
    except Exception as e:
        import traceback
        print(f"Error creating user: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'message': 'Failed to create user', 'error': str(e)}), 500

@app.route('/api/admin/users/<user_id>', methods=['GET'])
@token_required
@admin_required
def get_user_admin(current_user, user_id):
    """Get single user details (admin only)"""
    try:
        user = execute_query("""
            SELECT 
                u.id,
                u.email,
                u.name,
                u.role,
                u.department,
                u.phone,
                u.avatar,
                u.bio,
                u.timezone,
                u.created_at,
                u.last_login,
                (SELECT COUNT(DISTINCT pm.project_id) 
                 FROM project_members pm 
                 WHERE pm.user_id = u.id) as project_count,
                (SELECT COUNT(*) 
                 FROM tasks t 
                 WHERE t.assignee_id = u.id) as total_tasks,
                (SELECT COUNT(*) 
                 FROM tasks t 
                 WHERE t.assignee_id = u.id 
                 AND t.status = 'done') as completed_tasks
            FROM users u
            WHERE u.id = %s
        """, (user_id,), fetch_one=True)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        u_dict = dict(user)
        
        # Get user's projects
        projects = execute_query("""
            SELECT 
                p.id,
                p.name,
                pm.role as project_role,
                pm.joined_at
            FROM project_members pm
            LEFT JOIN projects p ON pm.project_id = p.id
            WHERE pm.user_id = %s
            ORDER BY pm.joined_at DESC
        """, (user_id,))
        
        return jsonify({
            'user': {
                'id': u_dict['id'],
                'email': u_dict['email'],
                'name': u_dict.get('name'),
                'role': u_dict.get('role', 'member'),
                'department': u_dict.get('department'),
                'phone': u_dict.get('phone'),
                'avatar': u_dict.get('avatar'),
                'bio': u_dict.get('bio'),
                'timezone': u_dict.get('timezone'),
                'createdAt': u_dict['created_at'].isoformat() if u_dict.get('created_at') else None,
                'lastLogin': u_dict['last_login'].isoformat() if u_dict.get('last_login') else None,
                'projectCount': u_dict.get('project_count', 0),
                'totalTasks': u_dict.get('total_tasks', 0),
                'completedTasks': u_dict.get('completed_tasks', 0),
                'projects': [dict(p) for p in projects]
            }
        }), 200
        
    except Exception as e:
        print(f"Error fetching user: {str(e)}")
        return jsonify({'message': 'Failed to fetch user', 'error': str(e)}), 500

@app.route('/api/admin/users/<user_id>', methods=['PUT'])
@token_required
@admin_required
def update_user_admin(current_user, user_id):
    """Update user (admin only)"""
    try:
        data = request.get_json()
        
        allowed_fields = ['name', 'role', 'department', 'phone', 'bio', 'avatar', 'timezone']
        
        updates = {}
        for field in allowed_fields:
            if field in data:
                updates[field] = data[field]
        
        if not updates:
            return jsonify({'message': 'No valid fields to update'}), 400
        
        set_clause = ", ".join([f"{k} = %s" for k in updates.keys()])
        values = list(updates.values()) + [user_id]
        
        execute_query(
            f"UPDATE users SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            values,
            fetch=False
        )
        
        # Clear cache
        cache.delete(f"user_{user_id}")
        
        return jsonify({'message': 'User updated successfully'}), 200
        
    except Exception as e:
        import traceback
        print(f"Error updating user: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'message': 'Failed to update user', 'error': str(e)}), 500

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_user_admin(current_user, user_id):
    """Delete user (admin only)"""
    try:
        # Prevent self-deletion
        if user_id == current_user['id']:
            return jsonify({'message': 'You cannot delete your own account'}), 400
        
        # Check if user exists
        user = execute_query(
            "SELECT id, email FROM users WHERE id = %s",
            (user_id,),
            fetch_one=True
        )
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Delete user (cascading deletes will handle related records)
        execute_query(
            "DELETE FROM users WHERE id = %s",
            (user_id,),
            fetch=False
        )
        
        # Clear cache
        cache.delete(f"user_{user_id}")
        
        return jsonify({'message': 'User deleted successfully'}), 200
        
    except Exception as e:
        import traceback
        print(f"Error deleting user: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'message': 'Failed to delete user', 'error': str(e)}), 500

@app.route('/api/admin/users/<user_id>/reset-password', methods=['POST'])
@token_required
@admin_required
def reset_user_password_admin(current_user, user_id):
    """Reset user password (admin only)"""
    try:
        data = request.get_json()
        new_password = data.get('password', '')
        
        if not new_password or len(new_password) < 6:
            return jsonify({'message': 'Password must be at least 6 characters'}), 400
        
        # Hash new password
        password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        execute_query(
            "UPDATE users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (password_hash, user_id),
            fetch=False
        )
        
        return jsonify({'message': 'Password reset successfully'}), 200
        
    except Exception as e:
        print(f"Error resetting password: {str(e)}")
        return jsonify({'message': 'Failed to reset password', 'error': str(e)}), 500

@app.route('/api/admin/stats', methods=['GET'])
@token_required
@admin_required
def get_admin_stats(current_user):
    """Get admin dashboard statistics"""
    try:
        stats = execute_query("""
            SELECT 
                (SELECT COUNT(*) FROM users) as total_users,
                (SELECT COUNT(*) FROM users WHERE role = 'admin') as admin_count,
                (SELECT COUNT(*) FROM users WHERE role = 'member') as member_count,
                (SELECT COUNT(*) FROM projects) as total_projects,
                (SELECT COUNT(*) FROM tasks) as total_tasks,
                (SELECT COUNT(*) FROM tasks WHERE status = 'done') as completed_tasks,
                (SELECT COUNT(*) FROM users WHERE last_login > NOW() - INTERVAL '7 days') as active_users_week,
                (SELECT COUNT(*) FROM users WHERE created_at > NOW() - INTERVAL '30 days') as new_users_month
        """, fetch_one=True)
        
        return jsonify({'stats': dict(stats)}), 200
        
    except Exception as e:
        print(f"Error fetching admin stats: {str(e)}")
        return jsonify({'message': 'Failed to fetch stats', 'error': str(e)}), 500

@app.route('/api/projects', methods=['POST'])
@token_required
def create_project(current_user):
    """Create new project"""
    data = request.get_json()
    
    project_id = secrets.token_hex(16)
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Create project
            cur.execute("""
                INSERT INTO projects (id, name, description, status, priority, start_date, end_date, color, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                project_id,
                data['name'],
                data.get('description'),
                data.get('status', 'active'),
                data.get('priority', 'medium'),
                data.get('start_date'),
                data.get('end_date'),
                data.get('color', '#3b82f6'),
                current_user['id']
            ))
            
            # Add creator as owner
            cur.execute("""
                INSERT INTO project_members (project_id, user_id, role)
                VALUES (%s, %s, 'owner')
            """, (project_id, current_user['id']))
            
            conn.commit()
    finally:
        return_db_connection(conn)
    
    cache.delete_memoized(get_projects)
    
    return jsonify({'message': 'Project created', 'id': project_id}), 201

@app.route('/api/projects/<project_id>', methods=['GET'])
@token_required
def get_project(current_user, project_id):
    """Get single project with details"""
    project = execute_query("""
        SELECT p.*,
               json_agg(DISTINCT jsonb_build_object('id', u.id, 'name', u.name, 'email', u.email, 'role', pm.role)) as members
        FROM projects p
        LEFT JOIN project_members pm ON p.id = pm.project_id
        LEFT JOIN users u ON pm.user_id = u.id
        WHERE p.id = %s
        GROUP BY p.id
    """, (project_id,), fetch_one=True)
    
    if not project:
        return jsonify({'message': 'Project not found'}), 404
    
    return jsonify({'project': dict(project)}), 200

@app.route('/api/projects/<project_id>', methods=['PUT'])
@token_required
def update_project(current_user, project_id):
    """Update project"""
    data = request.get_json()
    allowed_fields = ['name', 'description', 'status', 'priority', 'start_date', 'end_date', 'color']
    
    updates = {k: v for k, v in data.items() if k in allowed_fields}
    if not updates:
        return jsonify({'message': 'No valid fields'}), 400
    
    set_clause = ", ".join([f"{k} = %s" for k in updates.keys()])
    values = list(updates.values()) + [project_id]
    
    execute_query(
        f"UPDATE projects SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
        values,
        fetch=False
    )
    
    cache.delete_memoized(get_projects)
    
    return jsonify({'message': 'Project updated'}), 200

@app.route('/api/projects/<project_id>', methods=['DELETE'])
@token_required
def delete_project(current_user, project_id):
    """Delete project"""
    execute_query("DELETE FROM projects WHERE id = %s AND created_by = %s", (project_id, current_user['id']), fetch=False)
    cache.delete_memoized(get_projects)
    return jsonify({'message': 'Project deleted'}), 200

def project_admin_required(f):
    """Decorator to check if user is project admin/owner"""
    @wraps(f)
    def decorated(current_user, project_id, *args, **kwargs):
        # Check if user is system admin
        if current_user.get('role') == 'admin':
            return f(current_user, project_id, *args, **kwargs)
        
        # Check if user is project owner/admin
        member_role = execute_query("""
            SELECT pm.role 
            FROM project_members pm
            WHERE pm.project_id = %s AND pm.user_id = %s
        """, (project_id, current_user['id']), fetch_one=True)
        
        if not member_role or member_role['role'] not in ['owner', 'admin']:
            return jsonify({'message': 'Only project admins can perform this action'}), 403
        
        return f(current_user, project_id, *args, **kwargs)
    
    return decorated

@app.route('/api/projects/<project_id>/members', methods=['POST'])
@token_required
@project_admin_required
def add_project_member(current_user, project_id):
    """Add a user to a project (admin/owner only)"""
    try:
        data = request.get_json()
        user_email = data.get('email', '').strip().lower()
        role = data.get('role', 'member')
        
        if not user_email:
            return jsonify({'message': 'Email is required'}), 400
        
        # Validate role
        valid_roles = ['member', 'admin']
        if role not in valid_roles:
            return jsonify({'message': 'Invalid role. Must be member or admin'}), 400
        
        # 1. Find the user by email
        user = execute_query(
            "SELECT id, name, email FROM users WHERE email = %s", 
            (user_email,), 
            fetch_one=True
        )
        
        if not user:
            return jsonify({'message': 'User not found with this email'}), 404
        
        # 2. Check if already a member
        existing = execute_query("""
            SELECT id, role FROM project_members 
            WHERE project_id = %s AND user_id = %s
        """, (project_id, user['id']), fetch_one=True)
        
        if existing:
            return jsonify({
                'message': 'User is already a member of this project',
                'currentRole': existing['role']
            }), 409
        
        # 3. Insert new member
        execute_query("""
            INSERT INTO project_members (project_id, user_id, role, joined_at)
            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
        """, (project_id, user['id'], role), fetch=False)
        
        # Clear cache
        cache.delete_memoized(get_project_members, current_user, project_id)
        
        return jsonify({
            'message': 'Member added successfully',
            'member': {
                'id': user['id'],
                'name': user.get('name'),
                'email': user['email'],
                'role': role
            }
        }), 201
        
    except Exception as e:
        import traceback
        print(f"Error adding member: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'message': 'Failed to add member', 'error': str(e)}), 500

@app.route('/api/projects/<project_id>/members/<user_id>', methods=['DELETE'])
@token_required
@project_admin_required
def remove_project_member(current_user, project_id, user_id):
    """Remove a member from a project (admin/owner only)"""
    try:
        # Cannot remove project owner
        target_role = execute_query("""
            SELECT role FROM project_members 
            WHERE project_id = %s AND user_id = %s
        """, (project_id, user_id), fetch_one=True)
        
        if not target_role:
            return jsonify({'message': 'Member not found in this project'}), 404
        
        if target_role['role'] == 'owner':
            return jsonify({'message': 'Cannot remove project owner'}), 403
        
        if user_id == current_user['id']:
            user_role = execute_query("""
                SELECT role FROM project_members 
                WHERE project_id = %s AND user_id = %s
            """, (project_id, current_user['id']), fetch_one=True)
            
            if user_role and user_role['role'] == 'owner':
                return jsonify({'message': 'Owner cannot remove themselves'}), 403
        
        # Remove member
        execute_query("""
            DELETE FROM project_members 
            WHERE project_id = %s AND user_id = %s
        """, (project_id, user_id), fetch=False)
        
        # Unassign tasks assigned to this user in this project
        execute_query("""
            UPDATE tasks 
            SET assignee_id = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE project_id = %s AND assignee_id = %s
        """, (project_id, user_id), fetch=False)
        
        cache.delete_memoized(get_project_members, current_user, project_id)
        
        return jsonify({'message': 'Member removed successfully'}), 200
        
    except Exception as e:
        import traceback
        print(f"Error removing member: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'message': 'Failed to remove member', 'error': str(e)}), 500

@app.route('/api/projects/<project_id>/members/<user_id>/role', methods=['PUT'])
@token_required
@project_admin_required
def update_member_role(current_user, project_id, user_id):
    """Update a member's role (admin/owner only)"""
    try:
        data = request.get_json()
        new_role = data.get('role', '').strip().lower()
        
        if new_role not in ['member', 'admin']:
            return jsonify({'message': 'Invalid role. Must be member or admin'}), 400
        
        # Cannot change owner role
        current_role = execute_query("""
            SELECT role FROM project_members 
            WHERE project_id = %s AND user_id = %s
        """, (project_id, user_id), fetch_one=True)
        
        if not current_role:
            return jsonify({'message': 'Member not found'}), 404
        
        if current_role['role'] == 'owner':
            return jsonify({'message': 'Cannot change owner role'}), 403
        
        # Update role
        execute_query("""
            UPDATE project_members 
            SET role = %s, updated_at = CURRENT_TIMESTAMP
            WHERE project_id = %s AND user_id = %s
        """, (new_role, project_id, user_id), fetch=False)
        
        cache.delete_memoized(get_project_members, current_user, project_id)
        
        return jsonify({'message': 'Member role updated successfully'}), 200
        
    except Exception as e:
        print(f"Error updating member role: {str(e)}")
        return jsonify({'message': 'Failed to update role', 'error': str(e)}), 500

# ============================================
# TASK ENDPOINTS - Optimized with Batch Operations
# ============================================
@app.route('/api/projects/<project_id>/tasks', methods=['GET'])
@token_required
@cache.cached(timeout=15, query_string=True)
def get_tasks(current_user, project_id):
    """Get all tasks for project - OPTIMIZED with membership validation"""
    try:
        # Verify user has access to this project
        is_member = execute_query("""
            SELECT id FROM project_members 
            WHERE project_id = %s AND user_id = %s
        """, (project_id, current_user['id']), fetch_one=True)
        
        if not is_member:
            return jsonify({'message': 'You must be a project member to view tasks'}), 403
        
        tasks = execute_query("""
            SELECT t.*,
                   u.name as assignee_name,
                   u.email as assignee_email,
                   u.avatar as assignee_avatar,
                   r.name as reporter_name,
                   m.name as milestone_name,
                   (SELECT COUNT(*) FROM task_comments WHERE task_id = t.id) as comment_count,
                   -- Check if assignee is still a member
                   CASE 
                       WHEN t.assignee_id IS NULL THEN true
                       WHEN EXISTS (
                           SELECT 1 FROM project_members pm 
                           WHERE pm.project_id = t.project_id 
                           AND pm.user_id = t.assignee_id
                       ) THEN true
                       ELSE false
                   END as assignee_is_member
            FROM tasks t
            LEFT JOIN users u ON t.assignee_id = u.id
            LEFT JOIN users r ON t.reporter_id = r.id
            LEFT JOIN milestones m ON t.milestone_id = m.id
            WHERE t.project_id = %s
            ORDER BY t.position ASC, t.created_at DESC
        """, (project_id,))
        
        return jsonify({'tasks': [dict(t) for t in tasks]}), 200
        
    except Exception as e:
        print(f"Error fetching tasks: {str(e)}")
        return jsonify({'message': 'Failed to fetch tasks', 'error': str(e)}), 500

@app.route('/api/projects/<project_id>/tasks', methods=['POST'])
@token_required
def create_task(current_user, project_id):
    """Create new task with membership validation"""
    try:
        data = request.get_json()
        task_id = secrets.token_hex(16)
        
        # Verify user has access to this project
        is_member = execute_query("""
            SELECT id FROM project_members 
            WHERE project_id = %s AND user_id = %s
        """, (project_id, current_user['id']), fetch_one=True)
        
        if not is_member:
            return jsonify({'message': 'You must be a project member to create tasks'}), 403
        
        # Validate assignee is a project member (if assignee provided)
        assignee_id = data.get('assignee_id')
        if assignee_id:
            assignee_is_member = execute_query("""
                SELECT id FROM project_members 
                WHERE project_id = %s AND user_id = %s
            """, (project_id, assignee_id), fetch_one=True)
            
            if not assignee_is_member:
                return jsonify({
                    'message': 'Cannot assign task to user who is not a project member',
                    'error': 'ASSIGNEE_NOT_MEMBER'
                }), 400
        
        # Create task
        execute_query("""
            INSERT INTO tasks (
                id, 
                project_id, 
                title, 
                description, 
                status, 
                priority, 
                assignee_id, 
                reporter_id, 
                due_date, 
                position, 
                type
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            task_id,
            project_id,
            data['title'],
            data.get('description'),
            data.get('status', 'todo'),
            data.get('priority', 'medium'),
            assignee_id,  # Can be None/null
            current_user['id'],  # Reporter is current user
            data.get('due_date'),
            data.get('position', 0),
            data.get('type', 'task')
        ), fetch=False)
        
        # Clear relevant caches
        cache.delete_memoized(get_tasks, current_user, project_id)
        if assignee_id:
            cache.delete(f"user_{assignee_id}")
        
        return jsonify({
            'message': 'Task created successfully',
            'id': task_id
        }), 201
        
    except Exception as e:
        print(f"Error creating task: {str(e)}")
        return jsonify({'message': 'Failed to create task', 'error': str(e)}), 500

@app.route('/api/tasks/<task_id>', methods=['PUT'])
@token_required
def update_task(current_user, task_id):
    """Update task"""
    data = request.get_json()
    allowed_fields = ['title', 'description', 'status', 'priority', 'assignee_id', 'due_date', 'position', 'type', 'milestone_id']
    
    updates = {k: v for k, v in data.items() if k in allowed_fields}
    if not updates:
        return jsonify({'message': 'No valid fields'}), 400
    
    set_clause = ", ".join([f"{k} = %s" for k in updates.keys()])
    values = list(updates.values()) + [task_id]
    
    execute_query(
        f"UPDATE tasks SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
        values,
        fetch=False
    )
    
    return jsonify({'message': 'Task updated'}), 200

@app.route('/api/tasks/bulk-update', methods=['PUT'])
@token_required
def bulk_update_tasks(current_user):
    """Bulk update tasks (for Kanban drag-drop) - OPTIMIZED"""
    data = request.get_json()
    updates = data.get('updates', [])  # [{'id': '...', 'status': '...', 'position': 0}]
    
    if not updates:
        return jsonify({'message': 'No updates provided'}), 400
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            execute_batch(cur, """
                UPDATE tasks 
                SET status = %(status)s, position = %(position)s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %(id)s
            """, updates)
            conn.commit()
    finally:
        return_db_connection(conn)
    
    return jsonify({'message': 'Tasks updated'}), 200

@app.route('/api/tasks/<task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
    """Delete task"""
    execute_query("DELETE FROM tasks WHERE id = %s", (task_id,), fetch=False)
    return jsonify({'message': 'Task deleted'}), 200

# ============================================
# DISCUSSION/CHAT ENDPOINTS
# ============================================
@app.route('/api/projects/<project_id>/discussions', methods=['GET'])
@token_required
def get_discussions(current_user, project_id):
    """Get discussions - OPTIMIZED with limit"""
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    
    discussions = execute_query("""
        SELECT d.*,
               u.name as user_name,
               u.avatar as user_avatar
        FROM discussions d
        LEFT JOIN users u ON d.user_id = u.id
        WHERE d.project_id = %s
        ORDER BY d.created_at DESC
        LIMIT %s OFFSET %s
    """, (project_id, limit, offset))
    
    return jsonify({'discussions': [dict(d) for d in discussions]}), 200

@app.route('/api/projects/<project_id>/discussions', methods=['POST'])
@token_required
def create_discussion(current_user, project_id):
    """Post message"""
    data = request.get_json()
    discussion_id = secrets.token_hex(16)
    
    execute_query("""
        INSERT INTO discussions (id, project_id, user_id, message, reply_to)
        VALUES (%s, %s, %s, %s, %s)
    """, (
        discussion_id,
        project_id,
        current_user['id'],
        data['message'],
        data.get('reply_to')
    ), fetch=False)
    
    return jsonify({'message': 'Message posted', 'id': discussion_id}), 201


@app.route('/api/projects/<project_id>/members', methods=['GET'])
@token_required
def get_project_members(current_user, project_id):
    """Get all members of a project"""
    try:
        # Verify user has access to this project
        access_check = execute_query("""
            SELECT pm.role 
            FROM project_members pm
            WHERE pm.project_id = %s AND pm.user_id = %s
        """, (project_id, current_user['id']), fetch_one=True)
        
        if not access_check:
            # Also check if user is project creator
            creator_check = execute_query("""
                SELECT id FROM projects WHERE id = %s AND created_by = %s
            """, (project_id, current_user['id']), fetch_one=True)
            
            if not creator_check:
                return jsonify({'message': 'You do not have access to this project'}), 403
        
        # Get all project members with their details
        members = execute_query("""
            SELECT 
                u.id,
                u.name,
                u.email,
                u.avatar,
                u.role as user_role,
                pm.role as project_role,
                pm.joined_at
            FROM project_members pm
            LEFT JOIN users u ON pm.user_id = u.id
            WHERE pm.project_id = %s
            ORDER BY 
                CASE pm.role
                    WHEN 'owner' THEN 1
                    WHEN 'admin' THEN 2
                    WHEN 'member' THEN 3
                    ELSE 4
                END,
                u.name ASC
        """, (project_id,))
        
        return jsonify({
            'members': [dict(m) for m in members],
            'total': len(members)
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to fetch project members', 'error': str(e)}), 500

# ============================================
# MY TASKS ENDPOINT - Get all tasks for current user
# ============================================
@app.route('/api/my-tasks', methods=['GET'])
@token_required
def get_my_tasks(current_user):
    """Get all tasks assigned to current user - ONLY from projects they're members of"""
    try:
        project_id = request.args.get('project_id')
        status = request.args.get('status')
        priority = request.args.get('priority')
        
        # Build query - IMPORTANT: Only get tasks from projects user is member of
        query = """
            SELECT t.*,
                   p.name as project_name,
                   p.color as project_color,
                   u.name as assignee_name,
                   u.email as assignee_email,
                   u.avatar as assignee_avatar,
                   r.name as reporter_name,
                   m.name as milestone_name,
                   (SELECT COUNT(*) FROM task_comments WHERE task_id = t.id) as comment_count
            FROM tasks t
            LEFT JOIN projects p ON t.project_id = p.id
            LEFT JOIN users u ON t.assignee_id = u.id
            LEFT JOIN users r ON t.reporter_id = r.id
            LEFT JOIN milestones m ON t.milestone_id = m.id
            WHERE t.assignee_id = %s
            -- CRITICAL: Only show tasks from projects user is member of
            AND EXISTS (
                SELECT 1 FROM project_members pm
                WHERE pm.project_id = t.project_id
                AND pm.user_id = %s
            )
        """
        
        params = [current_user['id'], current_user['id']]
        
        # Add filters
        if project_id:
            query += " AND t.project_id = %s"
            params.append(project_id)
        
        if status:
            query += " AND t.status = %s"
            params.append(status)
        
        if priority:
            query += " AND t.priority = %s"
            params.append(priority)
        
        query += " ORDER BY t.position ASC, t.created_at DESC"
        
        tasks = execute_query(query, tuple(params))
        
        return jsonify({
            'tasks': [dict(t) for t in tasks],
            'total': len(tasks)
        }), 200
        
    except Exception as e:
        print(f"Error fetching my tasks: {str(e)}")
        return jsonify({'message': 'Failed to fetch tasks', 'error': str(e)}), 500

# ============================================
# GET USER'S PROJECTS - For filter dropdown
# ============================================
@app.route('/api/my-projects', methods=['GET'])
@token_required
@cache.cached(timeout=60, query_string=True)
def get_my_projects(current_user):
    """Get all projects where user is a member - for filter dropdown"""
    try:
        projects = execute_query("""
            SELECT DISTINCT p.id, p.name, p.color, p.status
            FROM projects p
            LEFT JOIN project_members pm ON p.id = pm.project_id
            WHERE pm.user_id = %s OR p.created_by = %s
            ORDER BY p.name ASC
        """, (current_user['id'], current_user['id']))
        
        return jsonify({
            'projects': [dict(p) for p in projects]
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to fetch projects', 'error': str(e)}), 500

# ============================================
# Get all projects 
# ============================================
@app.route('/api/projects', methods=['GET'])
@token_required
@cache.cached(timeout=30, query_string=True)
def get_projects(current_user):
    """Get projects based on user role - admins see all, users see only their projects"""
    try:
        # Check if user is admin
        user_role = current_user.get('role', 'member')
        
        if user_role == 'admin':
            # Admin sees ALL projects
            projects = execute_query("""
                SELECT DISTINCT p.*, 
                       pm.role as user_role,
                       u.name as created_by_name,
                       (SELECT COUNT(*) FROM tasks WHERE project_id = p.id) as task_count,
                       (SELECT COUNT(*) FROM tasks WHERE project_id = p.id AND status = 'done') as completed_tasks,
                       (SELECT COUNT(*) FROM project_members WHERE project_id = p.id) as member_count
                FROM projects p
                LEFT JOIN project_members pm ON p.id = pm.project_id AND pm.user_id = %s
                LEFT JOIN users u ON p.created_by = u.id
                ORDER BY p.updated_at DESC
            """, (current_user['id'],))
        else:
            # Regular users see only their projects
            projects = execute_query("""
                SELECT DISTINCT p.*, 
                       pm.role as user_role,
                       u.name as created_by_name,
                       (SELECT COUNT(*) FROM tasks WHERE project_id = p.id) as task_count,
                       (SELECT COUNT(*) FROM tasks WHERE project_id = p.id AND status = 'done') as completed_tasks,
                       (SELECT COUNT(*) FROM project_members WHERE project_id = p.id) as member_count
                FROM projects p
                LEFT JOIN project_members pm ON p.id = pm.project_id
                LEFT JOIN users u ON p.created_by = u.id
                WHERE pm.user_id = %s OR p.created_by = %s
                ORDER BY p.updated_at DESC
            """, (current_user['id'], current_user['id']))
        
        return jsonify({
            'projects': [dict(p) for p in projects],
            'is_admin': user_role == 'admin'
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to fetch projects', 'error': str(e)}), 500


# ============================================
# DASHBOARD STATS
# ============================================
@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
@cache.cached(timeout=60)
def get_dashboard_stats(current_user):
    """Get dashboard statistics - ONLY from projects user is member of"""
    stats = execute_query("""
        SELECT 
            (SELECT COUNT(*) 
             FROM tasks t
             WHERE t.assignee_id = %s 
             AND t.status NOT IN ('done', 'archived')
             AND EXISTS (
                 SELECT 1 FROM project_members pm
                 WHERE pm.project_id = t.project_id AND pm.user_id = %s
             )) as my_active_tasks,
            
            (SELECT COUNT(*) 
             FROM tasks t
             WHERE t.assignee_id = %s 
             AND t.due_date < CURRENT_DATE 
             AND t.status NOT IN ('done', 'archived')
             AND EXISTS (
                 SELECT 1 FROM project_members pm
                 WHERE pm.project_id = t.project_id AND pm.user_id = %s
             )) as overdue_tasks,
            
            (SELECT COUNT(DISTINCT project_id) 
             FROM project_members 
             WHERE user_id = %s) as my_projects,
            
            (SELECT COUNT(*) 
             FROM tasks t
             WHERE t.assignee_id = %s 
             AND t.status = 'done' 
             AND DATE(t.updated_at) = CURRENT_DATE
             AND EXISTS (
                 SELECT 1 FROM project_members pm
                 WHERE pm.project_id = t.project_id AND pm.user_id = %s
             )) as completed_today,
            
            (SELECT COUNT(*) 
             FROM tasks t
             WHERE t.assignee_id = %s 
             AND t.status = 'backlog'
             AND EXISTS (
                 SELECT 1 FROM project_members pm
                 WHERE pm.project_id = t.project_id AND pm.user_id = %s
             )) as backlog_count,
            
            (SELECT COUNT(*) 
             FROM tasks t
             WHERE t.assignee_id = %s 
             AND t.status = 'todo'
             AND EXISTS (
                 SELECT 1 FROM project_members pm
                 WHERE pm.project_id = t.project_id AND pm.user_id = %s
             )) as todo_count,
            
            (SELECT COUNT(*) 
             FROM tasks t
             WHERE t.assignee_id = %s 
             AND t.status = 'in_progress'
             AND EXISTS (
                 SELECT 1 FROM project_members pm
                 WHERE pm.project_id = t.project_id AND pm.user_id = %s
             )) as in_progress_count
    """, (
        current_user['id'], current_user['id'],  # my_active_tasks
        current_user['id'], current_user['id'],  # overdue_tasks
        current_user['id'],                       # my_projects
        current_user['id'], current_user['id'],  # completed_today
        current_user['id'], current_user['id'],  # backlog_count
        current_user['id'], current_user['id'],  # todo_count
        current_user['id'], current_user['id']   # in_progress_count
    ), fetch_one=True)
    
    return jsonify({'stats': dict(stats)}), 200

@app.route('/api/analytics/reports', methods=['GET'])
@token_required
@cache.cached(timeout=60) # Cache for 1 minute
def get_analytics_reports(current_user):
    """Fetch real-time analytics for reports page"""
    try:
        # 1. Task Distribution (Global across user's projects)
        distribution = execute_query("""
            SELECT status, COUNT(*) as count 
            FROM tasks 
            WHERE project_id IN (SELECT project_id FROM project_members WHERE user_id = %s)
            GROUP BY status
        """, (current_user['id'],))

        # 2. Weekly Productivity (Tasks completed in last 7 days)
        productivity = execute_query("""
            SELECT 
                to_char(updated_at, 'Dy') as label,
                COUNT(*) as value
            FROM tasks
            WHERE status = 'done' 
              AND updated_at > CURRENT_DATE - INTERVAL '7 days'
            GROUP BY label, updated_at::date
            ORDER BY updated_at::date ASC
        """, ())

        # 3. Team Workload Distribution
        workload = execute_query("""
            SELECT 
                u.name,
                COUNT(t.id) as tasks,
                ROUND((COUNT(CASE WHEN t.status = 'done' THEN 1 END)::float / 
                       NULLIF(COUNT(t.id), 0)::float) * 100) as percentage
            FROM users u
            JOIN project_members pm ON u.id = pm.user_id
            LEFT JOIN tasks t ON u.id = t.assignee_id
            WHERE pm.project_id IN (SELECT project_id FROM project_members WHERE user_id = %s)
            GROUP BY u.id, u.name
            LIMIT 5
        """, (current_user['id'],))

        return jsonify({
            'distribution': distribution,
            'productivity': productivity,
            'workload': workload
        }), 200
    except Exception as e:
        return jsonify({'message': 'Analytics failed', 'error': str(e)}), 500

# ============================================
# ENHANCED CHAT/DISCUSSION ENDPOINTS
# ============================================

@app.route('/api/chats', methods=['GET'])
@token_required
def get_user_chats(current_user):
    """Get all chat channels/discussions for current user"""
    try:
        # Get all project channels user has access to
        project_chats = execute_query("""
            SELECT DISTINCT
                'project_' || p.id as chat_id,
                'project' as chat_type,
                p.name as chat_name,
                p.color,
                (SELECT d.message 
                 FROM discussions d 
                 WHERE d.project_id = p.id 
                 ORDER BY d.created_at DESC 
                 LIMIT 1) as last_message,
                (SELECT u.name 
                 FROM discussions d 
                 LEFT JOIN users u ON d.user_id = u.id
                 WHERE d.project_id = p.id 
                 ORDER BY d.created_at DESC 
                 LIMIT 1) as last_sender,
                (SELECT d.created_at 
                 FROM discussions d 
                 WHERE d.project_id = p.id 
                 ORDER BY d.created_at DESC 
                 LIMIT 1) as last_message_time,
                (SELECT COUNT(*) 
                 FROM discussions d 
                 WHERE d.project_id = p.id 
                 AND d.created_at > COALESCE(
                     (SELECT last_read FROM chat_read_status 
                      WHERE user_id = %s AND chat_id = 'project_' || p.id),
                     '1970-01-01'
                 )) as unread_count,
                (SELECT COUNT(DISTINCT pm.user_id)
                 FROM project_members pm
                 WHERE pm.project_id = p.id) as member_count
            FROM projects p
            INNER JOIN project_members pm ON p.id = pm.project_id
            WHERE pm.user_id = %s
            ORDER BY last_message_time DESC NULLS LAST
        """, (current_user['id'], current_user['id']))
        
        # Get direct message chats (we'll implement this later if needed)
        # For now, just return project chats
        
        chats = []
        for chat in project_chats:
            chat_dict = dict(chat)
            # Format the chat object
            chats.append({
                'id': chat_dict['chat_id'],
                'type': chat_dict['chat_type'],
                'name': chat_dict['chat_name'],
                'color': chat_dict.get('color', '#3b82f6'),
                'lastMessage': chat_dict.get('last_message', 'No messages yet'),
                'lastSender': chat_dict.get('last_sender'),
                'lastMessageTime': chat_dict.get('last_message_time'),
                'unreadCount': chat_dict.get('unread_count', 0),
                'memberCount': chat_dict.get('member_count', 0),
                'initials': ''.join([word[0].upper() for word in chat_dict['chat_name'].split()[:2]])
            })
        
        return jsonify({
            'chats': chats,
            'total': len(chats)
        }), 200
        
    except Exception as e:
        print(f"Error fetching chats: {str(e)}")
        return jsonify({'message': 'Failed to fetch chats', 'error': str(e)}), 500


@app.route('/api/chats/<chat_id>/messages', methods=['GET'])
@token_required
def get_chat_messages(current_user, chat_id):
    """Get messages for a specific chat"""
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Extract project ID from chat_id (format: 'project_XXXXX')
        if chat_id.startswith('project_'):
            project_id = chat_id.replace('project_', '')
            
            # Verify user has access
            access_check = execute_query("""
                SELECT id FROM project_members 
                WHERE project_id = %s AND user_id = %s
            """, (project_id, current_user['id']), fetch_one=True)
            
            if not access_check:
                return jsonify({'message': 'Access denied'}), 403
            
            # Get messages
            messages = execute_query("""
                SELECT 
                    d.id,
                    d.message as text,
                    d.created_at,
                    d.reply_to,
                    u.id as user_id,
                    u.name as sender,
                    u.avatar,
                    d.user_id = %s as is_me
                FROM discussions d
                LEFT JOIN users u ON d.user_id = u.id
                WHERE d.project_id = %s
                ORDER BY d.created_at ASC
                LIMIT %s OFFSET %s
            """, (current_user['id'], project_id, limit, offset))
            
            # Format messages
            formatted_messages = []
            for msg in messages:
                msg_dict = dict(msg)
                formatted_messages.append({
                    'id': msg_dict['id'],
                    'text': msg_dict['text'],
                    'sender': msg_dict['sender'],
                    'userId': msg_dict['user_id'],
                    'avatar': msg_dict.get('avatar'),
                    'isMe': msg_dict['is_me'],
                    'time': msg_dict['created_at'].strftime('%H:%M') if msg_dict['created_at'] else '',
                    'timestamp': msg_dict['created_at'].isoformat() if msg_dict['created_at'] else None,
                    'replyTo': msg_dict.get('reply_to')
                })
            
            # Update read status
            execute_query("""
                INSERT INTO chat_read_status (user_id, chat_id, last_read)
                VALUES (%s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (user_id, chat_id) 
                DO UPDATE SET last_read = CURRENT_TIMESTAMP
            """, (current_user['id'], chat_id), fetch=False)
            
            return jsonify({
                'messages': formatted_messages,
                'total': len(formatted_messages),
                'projectId': project_id
            }), 200
        
        return jsonify({'message': 'Invalid chat ID'}), 400
        
    except Exception as e:
        print(f"Error fetching messages: {str(e)}")
        return jsonify({'message': 'Failed to fetch messages', 'error': str(e)}), 500


@app.route('/api/chats/<chat_id>/messages', methods=['POST'])
@token_required
def send_chat_message(current_user, chat_id):
    """Send a message to a chat"""
    try:
        data = request.get_json()
        message_text = data.get('message', '').strip()
        reply_to = data.get('reply_to')
        
        if not message_text:
            return jsonify({'message': 'Message text is required'}), 400
        
        # Extract project ID from chat_id
        if chat_id.startswith('project_'):
            project_id = chat_id.replace('project_', '')
            
            # Verify user has access
            access_check = execute_query("""
                SELECT id FROM project_members 
                WHERE project_id = %s AND user_id = %s
            """, (project_id, current_user['id']), fetch_one=True)
            
            if not access_check:
                return jsonify({'message': 'Access denied'}), 403
            
            # Create message
            message_id = secrets.token_hex(16)
            execute_query("""
                INSERT INTO discussions (id, project_id, user_id, message, reply_to, created_at)
                VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
            """, (message_id, project_id, current_user['id'], message_text, reply_to), fetch=False)
            
            # Get the created message with user info
            message = execute_query("""
                SELECT 
                    d.id,
                    d.message as text,
                    d.created_at,
                    d.reply_to,
                    u.id as user_id,
                    u.name as sender,
                    u.avatar,
                    true as is_me
                FROM discussions d
                LEFT JOIN users u ON d.user_id = u.id
                WHERE d.id = %s
            """, (message_id,), fetch_one=True)
            
            msg_dict = dict(message)
            formatted_message = {
                'id': msg_dict['id'],
                'text': msg_dict['text'],
                'sender': msg_dict['sender'],
                'userId': msg_dict['user_id'],
                'avatar': msg_dict.get('avatar'),
                'isMe': msg_dict['is_me'],
                'time': msg_dict['created_at'].strftime('%H:%M'),
                'timestamp': msg_dict['created_at'].isoformat(),
                'replyTo': msg_dict.get('reply_to')
            }
            
            return jsonify({
                'message': 'Message sent',
                'data': formatted_message
            }), 201
        
        return jsonify({'message': 'Invalid chat ID'}), 400
        
    except Exception as e:
        print(f"Error sending message: {str(e)}")
        return jsonify({'message': 'Failed to send message', 'error': str(e)}), 500


@app.route('/api/chats/<chat_id>/members', methods=['GET'])
@token_required
def get_chat_members(current_user, chat_id):
    """Get members of a chat (for online status, typing indicators, etc.)"""
    try:
        if chat_id.startswith('project_'):
            project_id = chat_id.replace('project_', '')
            
            # Verify access
            access_check = execute_query("""
                SELECT id FROM project_members 
                WHERE project_id = %s AND user_id = %s
            """, (project_id, current_user['id']), fetch_one=True)
            
            if not access_check:
                return jsonify({'message': 'Access denied'}), 403
            
            # Get members
            members = execute_query("""
                SELECT 
                    u.id,
                    u.name,
                    u.email,
                    u.avatar,
                    pm.role,
                    -- Simple online status (last active in last 5 minutes)
                    CASE 
                        WHEN u.last_login > NOW() - INTERVAL '5 minutes' THEN true
                        ELSE false
                    END as is_online
                FROM project_members pm
                LEFT JOIN users u ON pm.user_id = u.id
                WHERE pm.project_id = %s
                ORDER BY is_online DESC, u.name ASC
            """, (project_id,))
            
            formatted_members = []
            online_count = 0
            
            for member in members:
                m_dict = dict(member)
                if m_dict.get('is_online'):
                    online_count += 1
                    
                formatted_members.append({
                    'id': m_dict['id'],
                    'name': m_dict['name'],
                    'email': m_dict['email'],
                    'avatar': m_dict.get('avatar'),
                    'role': m_dict.get('role'),
                    'isOnline': m_dict.get('is_online', False)
                })
            
            return jsonify({
                'members': formatted_members,
                'total': len(formatted_members),
                'onlineCount': online_count
            }), 200
        
        return jsonify({'message': 'Invalid chat ID'}), 400
        
    except Exception as e:
        print(f"Error fetching chat members: {str(e)}")
        return jsonify({'message': 'Failed to fetch members', 'error': str(e)}), 500


@app.route('/api/chats/<chat_id>/mark-read', methods=['POST'])
@token_required
def mark_chat_read(current_user, chat_id):
    """Mark all messages in a chat as read"""
    try:
        execute_query("""
            INSERT INTO chat_read_status (user_id, chat_id, last_read)
            VALUES (%s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (user_id, chat_id) 
            DO UPDATE SET last_read = CURRENT_TIMESTAMP
        """, (current_user['id'], chat_id), fetch=False)
        
        return jsonify({'message': 'Chat marked as read'}), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to mark as read', 'error': str(e)}), 500

# ============================================
# HEALTH & UTILITY ENDPOINTS
# ============================================
@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    try:
        execute_query("SELECT 1", fetch_one=True)
        return jsonify({'status': 'healthy', 'database': 'connected'}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/', methods=['GET'])
def root():
    """API info"""
    return jsonify({
        'message': 'Flow Task Manager API',
        'version': '2.0.0',
        'status': 'optimized'
    }), 200

# ============================================
# ENHANCED MILESTONES/ROADMAP ENDPOINTS
# ============================================

@app.route('/api/milestones', methods=['GET'])
@token_required
def get_all_milestones(current_user):
    """Get all milestones from projects user is member of"""
    try:
        project_id = request.args.get('project_id')
        status = request.args.get('status')
        
        query = """
            SELECT 
                m.id,
                m.name as title,
                m.description,
                m.due_date,
                m.status,
                m.project_id,
                p.name as project_name,
                p.color as project_color,
                m.created_by,
                u.name as created_by_name,
                m.created_at,
                m.updated_at,
                -- Calculate progress based on tasks
                CASE 
                    WHEN (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id) = 0 
                    THEN 0
                    ELSE ROUND(
                        (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id AND status = 'done')::numeric / 
                        (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id)::numeric * 100
                    )
                END as progress,
                (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id) as task_count,
                (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id AND status = 'done') as completed_tasks
            FROM milestones m
            LEFT JOIN projects p ON m.project_id = p.id
            LEFT JOIN users u ON m.created_by = u.id
            WHERE EXISTS (
                SELECT 1 FROM project_members pm
                WHERE pm.project_id = m.project_id
                AND pm.user_id = %s
            )
        """
        
        params = [current_user['id']]
        
        # Filter by project
        if project_id:
            query += " AND m.project_id = %s"
            params.append(project_id)
        
        # Filter by status
        if status:
            query += " AND m.status = %s"
            params.append(status)
        
        query += " ORDER BY m.due_date ASC NULLS LAST, m.created_at DESC"
        
        milestones = execute_query(query, tuple(params))
        
        formatted_milestones = []
        for milestone in milestones:
            m_dict = dict(milestone)
            formatted_milestones.append({
                'id': m_dict['id'],
                'title': m_dict['title'],
                'description': m_dict.get('description'),
                'date': m_dict['due_date'].strftime('%b %d, %Y') if m_dict.get('due_date') else None,
                'dueDate': m_dict['due_date'].isoformat() if m_dict.get('due_date') else None,
                'status': m_dict.get('status', 'pending'),
                'progress': int(m_dict.get('progress', 0)),
                'projectId': m_dict.get('project_id'),
                'projectName': m_dict.get('project_name'),
                'projectColor': m_dict.get('project_color'),
                'taskCount': m_dict.get('task_count', 0),
                'completedTasks': m_dict.get('completed_tasks', 0),
                'createdBy': m_dict.get('created_by'),
                'createdByName': m_dict.get('created_by_name'),
                'createdAt': m_dict['created_at'].isoformat() if m_dict.get('created_at') else None
            })
        
        return jsonify({
            'milestones': formatted_milestones,
            'total': len(formatted_milestones)
        }), 200
        
    except Exception as e:
        import traceback
        print(f"Error fetching milestones: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'message': 'Failed to fetch milestones', 'error': str(e)}), 500

@app.route('/api/projects/<project_id>/milestones', methods=['GET'])
@token_required
def get_milestones(current_user, project_id):
    """Get milestones for specific project"""
    try:
        # Verify user has access
        access_check = execute_query("""
            SELECT id FROM project_members 
            WHERE project_id = %s AND user_id = %s
        """, (project_id, current_user['id']), fetch_one=True)
        
        if not access_check:
            return jsonify({'message': 'Access denied'}), 403
        
        milestones = execute_query("""
            SELECT 
                m.*,
                (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id) as task_count,
                (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id AND status = 'done') as completed_tasks,
                CASE 
                    WHEN (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id) = 0 
                    THEN 0
                    ELSE ROUND(
                        (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id AND status = 'done')::numeric / 
                        (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id)::numeric * 100
                    )
                END as progress
            FROM milestones m
            WHERE m.project_id = %s
            ORDER BY m.due_date ASC
        """, (project_id,))
        
        return jsonify({'milestones': [dict(m) for m in milestones]}), 200
        
    except Exception as e:
        print(f"Error fetching project milestones: {str(e)}")
        return jsonify({'message': 'Failed to fetch milestones', 'error': str(e)}), 500

@app.route('/api/projects/<project_id>/milestones', methods=['POST'])
@token_required
def create_milestone(current_user, project_id):
    """Create new milestone"""
    try:
        data = request.get_json()
        
        # Verify user has access
        access_check = execute_query("""
            SELECT id FROM project_members 
            WHERE project_id = %s AND user_id = %s
        """, (project_id, current_user['id']), fetch_one=True)
        
        if not access_check:
            return jsonify({'message': 'Access denied'}), 403
        
        title = data.get('title', '').strip()
        if not title:
            return jsonify({'message': 'Milestone title is required'}), 400
        
        milestone_id = secrets.token_hex(16)
        
        execute_query("""
            INSERT INTO milestones (
                id, project_id, name, description, due_date, status, created_by, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        """, (
            milestone_id,
            project_id,
            title,
            data.get('description'),
            data.get('dueDate') or data.get('due_date'),
            data.get('status', 'pending'),
            current_user['id']
        ), fetch=False)
        
        return jsonify({
            'message': 'Milestone created successfully',
            'id': milestone_id
        }), 201
        
    except Exception as e:
        import traceback
        print(f"Error creating milestone: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'message': 'Failed to create milestone', 'error': str(e)}), 500

@app.route('/api/milestones/<milestone_id>', methods=['GET'])
@token_required
def get_milestone_details(current_user, milestone_id):
    """Get single milestone with details"""
    try:
        milestone = execute_query("""
            SELECT 
                m.*,
                p.name as project_name,
                p.color as project_color,
                u.name as created_by_name,
                (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id) as task_count,
                (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id AND status = 'done') as completed_tasks,
                CASE 
                    WHEN (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id) = 0 
                    THEN 0
                    ELSE ROUND(
                        (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id AND status = 'done')::numeric / 
                        (SELECT COUNT(*) FROM tasks WHERE milestone_id = m.id)::numeric * 100
                    )
                END as progress
            FROM milestones m
            LEFT JOIN projects p ON m.project_id = p.id
            LEFT JOIN users u ON m.created_by = u.id
            WHERE m.id = %s
            AND EXISTS (
                SELECT 1 FROM project_members pm
                WHERE pm.project_id = m.project_id
                AND pm.user_id = %s
            )
        """, (milestone_id, current_user['id']), fetch_one=True)
        
        if not milestone:
            return jsonify({'message': 'Milestone not found'}), 404
        
        # Get tasks for this milestone
        tasks = execute_query("""
            SELECT id, title, status, priority, assignee_id
            FROM tasks
            WHERE milestone_id = %s
            ORDER BY position ASC
        """, (milestone_id,))
        
        milestone_dict = dict(milestone)
        milestone_dict['tasks'] = [dict(t) for t in tasks]
        
        return jsonify({'milestone': milestone_dict}), 200
        
    except Exception as e:
        print(f"Error fetching milestone details: {str(e)}")
        return jsonify({'message': 'Failed to fetch milestone', 'error': str(e)}), 500

@app.route('/api/milestones/<milestone_id>', methods=['PUT'])
@token_required
def update_milestone(current_user, milestone_id):
    """Update milestone"""
    try:
        data = request.get_json()
        
        # Check if user has permission
        milestone = execute_query("""
            SELECT m.project_id, pm.id as is_member
            FROM milestones m
            LEFT JOIN project_members pm ON m.project_id = pm.project_id AND pm.user_id = %s
            WHERE m.id = %s
        """, (current_user['id'], milestone_id), fetch_one=True)
        
        if not milestone or not milestone.get('is_member'):
            return jsonify({'message': 'Permission denied'}), 403
        
        allowed_fields = ['name', 'description', 'due_date', 'status']
        
        updates = {}
        for field in allowed_fields:
            # Map frontend field names
            if field == 'name' and 'title' in data:
                updates['name'] = data['title']
            elif field == 'due_date' and 'dueDate' in data:
                updates['due_date'] = data['dueDate']
            elif field in data:
                updates[field] = data[field]
        
        if not updates:
            return jsonify({'message': 'No valid fields to update'}), 400
        
        set_clause = ", ".join([f"{k} = %s" for k in updates.keys()])
        values = list(updates.values()) + [milestone_id]
        
        execute_query(
            f"UPDATE milestones SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            values,
            fetch=False
        )
        
        return jsonify({'message': 'Milestone updated successfully'}), 200
        
    except Exception as e:
        import traceback
        print(f"Error updating milestone: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'message': 'Failed to update milestone', 'error': str(e)}), 500


@app.route('/api/milestones/<milestone_id>', methods=['DELETE'])
@token_required
def delete_milestone(current_user, milestone_id):
    """Delete milestone"""
    try:
        # Check if user has permission
        milestone = execute_query("""
            SELECT m.project_id, pm.id as is_member
            FROM milestones m
            LEFT JOIN project_members pm ON m.project_id = pm.project_id AND pm.user_id = %s
            WHERE m.id = %s
        """, (current_user['id'], milestone_id), fetch_one=True)
        
        if not milestone or not milestone.get('is_member'):
            return jsonify({'message': 'Permission denied'}), 403
        
        # Note: Tasks linked to this milestone will have milestone_id set to NULL (due to ON DELETE SET NULL)
        execute_query(
            "DELETE FROM milestones WHERE id = %s",
            (milestone_id,),
            fetch=False
        )
        
        return jsonify({'message': 'Milestone deleted successfully'}), 200
        
    except Exception as e:
        print(f"Error deleting milestone: {str(e)}")
        return jsonify({'message': 'Failed to delete milestone', 'error': str(e)}), 500


@app.route('/api/milestones/<milestone_id>/tasks', methods=['GET'])
@token_required
def get_milestone_tasks(current_user, milestone_id):
    """Get all tasks for a milestone"""
    try:
        # Verify access
        milestone = execute_query("""
            SELECT m.project_id
            FROM milestones m
            WHERE m.id = %s
            AND EXISTS (
                SELECT 1 FROM project_members pm
                WHERE pm.project_id = m.project_id
                AND pm.user_id = %s
            )
        """, (milestone_id, current_user['id']), fetch_one=True)
        
        if not milestone:
            return jsonify({'message': 'Milestone not found or access denied'}), 404
        
        tasks = execute_query("""
            SELECT 
                t.*,
                u.name as assignee_name,
                u.email as assignee_email
            FROM tasks t
            LEFT JOIN users u ON t.assignee_id = u.id
            WHERE t.milestone_id = %s
            ORDER BY t.position ASC, t.created_at DESC
        """, (milestone_id,))
        
        return jsonify({
            'tasks': [dict(t) for t in tasks],
            'total': len(tasks)
        }), 200
        
    except Exception as e:
        print(f"Error fetching milestone tasks: {str(e)}")
        return jsonify({'message': 'Failed to fetch tasks', 'error': str(e)}), 500

# ============================================
# MILESTONE STATUS OPTIONS
# ============================================
@app.route('/api/milestone-statuses', methods=['GET'])
@token_required
def get_milestone_statuses(current_user):
    """Get available milestone statuses"""
    return jsonify({
        'statuses': [
            {'value': 'pending', 'label': 'Pending', 'color': 'slate'},
            {'value': 'active', 'label': 'Active', 'color': 'blue'},
            {'value': 'completed', 'label': 'Completed', 'color': 'emerald'},
            {'value': 'on-hold', 'label': 'On Hold', 'color': 'amber'},
            {'value': 'cancelled', 'label': 'Cancelled', 'color': 'red'}
        ]
    }), 200

# ============================================
# ENHANCED CALENDAR ENDPOINTS
# ============================================

@app.route('/api/calendar/events', methods=['GET'])
@token_required
def get_calendar_events(current_user):
    """Get calendar events for current user with filters"""
    try:
        start_date = request.args.get('start')
        end_date = request.args.get('end')
        project_id = request.args.get('project_id')
        event_type = request.args.get('type')
        
        # First check if table exists and get its columns
        table_check = execute_query("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'calendar_events'
        """)
        
        if not table_check:
            # Table doesn't exist yet, return empty
            return jsonify({'events': [], 'total': 0}), 200
        
        # Check which all_day column exists
        columns = [row['column_name'] for row in table_check]
        all_day_column = 'is_all_day' if 'is_all_day' in columns else ('all_day' if 'all_day' in columns else None)
        
        # Build the SELECT clause dynamically
        all_day_select = f"ce.{all_day_column} as all_day" if all_day_column else "FALSE as all_day"
        
        # Build query - only show events from projects user is member of
        query = f"""
            SELECT 
                ce.id,
                ce.title,
                ce.description,
                ce.event_type,
                ce.start_time,
                ce.end_time,
                {all_day_select},
                ce.location,
                ce.project_id,
                p.name as project_name,
                p.color as project_color,
                ce.task_id,
                t.title as task_title,
                ce.created_by,
                u.name as created_by_name
            FROM calendar_events ce
            LEFT JOIN projects p ON ce.project_id = p.id
            LEFT JOIN tasks t ON ce.task_id = t.id
            LEFT JOIN users u ON ce.created_by = u.id
            WHERE 1=1
        """
        
        params = []
        
        # Filter by date range
        if start_date:
            query += " AND ce.start_time >= %s"
            params.append(start_date)
        
        if end_date:
            query += " AND ce.end_time <= %s"
            params.append(end_date)
        
        # Filter by project
        if project_id:
            query += " AND ce.project_id = %s"
            params.append(project_id)
        
        # Filter by event type
        if event_type:
            query += " AND ce.event_type = %s"
            params.append(event_type)
        
        # Only show events from projects user is member of OR events they created
        query += """
            AND (
                ce.created_by = %s
                OR ce.project_id IS NULL
                OR EXISTS (
                    SELECT 1 FROM project_members pm
                    WHERE pm.project_id = ce.project_id
                    AND pm.user_id = %s
                )
            )
        """
        params.extend([current_user['id'], current_user['id']])
        
        query += " ORDER BY ce.start_time ASC"
        
        events = execute_query(query, tuple(params))
        
        formatted_events = []
        for event in events:
            e_dict = dict(event)
            formatted_events.append({
                'id': e_dict['id'],
                'title': e_dict['title'],
                'description': e_dict.get('description'),
                'type': e_dict.get('event_type', 'meeting'),
                'startTime': e_dict['start_time'].isoformat() if e_dict.get('start_time') else None,
                'endTime': e_dict['end_time'].isoformat() if e_dict.get('end_time') else None,
                'allDay': e_dict.get('all_day', False),
                'location': e_dict.get('location'),
                'projectId': e_dict.get('project_id'),
                'projectName': e_dict.get('project_name'),
                'projectColor': e_dict.get('project_color'),
                'taskId': e_dict.get('task_id'),
                'taskTitle': e_dict.get('task_title'),
                'createdBy': e_dict.get('created_by'),
                'createdByName': e_dict.get('created_by_name')
            })
        
        return jsonify({
            'events': formatted_events,
            'total': len(formatted_events)
        }), 200
        
    except Exception as e:
        import traceback
        print(f"Error fetching calendar events: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'message': 'Failed to fetch events', 'error': str(e)}), 500

@app.route('/api/calendar/events', methods=['POST'])
@token_required
def create_calendar_event(current_user):
    """Create a new calendar event"""
    try:
        data = request.get_json()
        
        title = data.get('title', '').strip()
        if not title:
            return jsonify({'message': 'Event title is required'}), 400
        
        event_type = data.get('type', 'meeting')
        start_time = data.get('startTime')
        project_id = data.get('projectId')
        
        if not start_time:
            return jsonify({'message': 'Start time is required'}), 400
        
        # If project_id provided, verify user has access
        if project_id:
            access_check = execute_query("""
                SELECT id FROM project_members 
                WHERE project_id = %s AND user_id = %s
            """, (project_id, current_user['id']), fetch_one=True)
            
            if not access_check:
                # Check if user is creator
                creator_check = execute_query("""
                    SELECT id FROM projects WHERE id = %s AND created_by = %s
                """, (project_id, current_user['id']), fetch_one=True)
                
                if not creator_check:
                    return jsonify({'message': 'You must be a project member to create events'}), 403
        
        event_id = secrets.token_hex(16)
        
        # Calculate end_time if not provided (default: 1 hour after start)
        end_time = data.get('endTime')
        if not end_time and start_time:
            from datetime import datetime, timedelta
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            end_dt = start_dt + timedelta(hours=1)
            end_time = end_dt.isoformat()
        
        # Check if column is all_day or is_all_day
        column_check = execute_query("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name = 'calendar_events' 
            AND column_name IN ('all_day', 'is_all_day')
            LIMIT 1
        """, fetch_one=True)
        
        all_day_col = column_check['column_name'] if column_check else 'all_day'
        
        execute_query(f"""
            INSERT INTO calendar_events (
                id, title, description, event_type, start_time, end_time,
                {all_day_col}, location, project_id, task_id, created_by, created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        """, (
            event_id,
            title,
            data.get('description'),
            event_type,
            start_time,
            end_time,
            data.get('allDay', False),
            data.get('location'),
            project_id,
            data.get('taskId'),
            current_user['id']
        ), fetch=False)
        
        return jsonify({
            'message': 'Event created successfully',
            'id': event_id
        }), 201
        
    except Exception as e:
        print(f"Error creating calendar event: {str(e)}")
        return jsonify({'message': 'Failed to create event', 'error': str(e)}), 500

@app.route('/api/calendar/events/<event_id>', methods=['PUT'])
@token_required
def update_calendar_event(current_user, event_id):
    """Update a calendar event"""
    try:
        data = request.get_json()
        
        # Check if user has permission (creator or project member)
        event = execute_query("""
            SELECT ce.*, pm.id as is_member
            FROM calendar_events ce
            LEFT JOIN project_members pm ON ce.project_id = pm.project_id AND pm.user_id = %s
            WHERE ce.id = %s
        """, (current_user['id'], event_id), fetch_one=True)
        
        if not event:
            return jsonify({'message': 'Event not found'}), 404
        
        if event['created_by'] != current_user['id'] and not event.get('is_member'):
            return jsonify({'message': 'Permission denied'}), 403
        
        allowed_fields = ['title', 'description', 'event_type', 'start_time', 'end_time', 
                         'is_all_day', 'all_day', 'location', 'project_id', 'task_id']
        
        updates = {}
        for field in allowed_fields:
            # Map frontend field names to database field names
            db_field = 'event_type' if field == 'type' else field
            db_field = field.replace('Time', '_time').replace('Day', '_day').replace('Id', '_id')
            
            if field in data or field.replace('_', '') in data:
                value = data.get(field) or data.get(field.replace('_', ''))
                updates[db_field] = value
        
        if not updates:
            return jsonify({'message': 'No valid fields to update'}), 400
        
        set_clause = ", ".join([f"{k} = %s" for k in updates.keys()])
        values = list(updates.values()) + [event_id]
        
        execute_query(
            f"UPDATE calendar_events SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            values,
            fetch=False
        )
        
        return jsonify({'message': 'Event updated successfully'}), 200
        
    except Exception as e:
        print(f"Error updating calendar event: {str(e)}")
        return jsonify({'message': 'Failed to update event', 'error': str(e)}), 500


@app.route('/api/calendar/events/<event_id>', methods=['DELETE'])
@token_required
def delete_calendar_event(current_user, event_id):
    """Delete a calendar event"""
    try:
        # Check if user has permission
        event = execute_query("""
            SELECT ce.created_by, pm.id as is_member
            FROM calendar_events ce
            LEFT JOIN project_members pm ON ce.project_id = pm.project_id AND pm.user_id = %s
            WHERE ce.id = %s
        """, (current_user['id'], event_id), fetch_one=True)
        
        if not event:
            return jsonify({'message': 'Event not found'}), 404
        
        # Only creator or project admin can delete
        if event['created_by'] != current_user['id'] and not event.get('is_member'):
            return jsonify({'message': 'Permission denied'}), 403
        
        execute_query(
            "DELETE FROM calendar_events WHERE id = %s",
            (event_id,),
            fetch=False
        )
        
        return jsonify({'message': 'Event deleted successfully'}), 200
        
    except Exception as e:
        print(f"Error deleting calendar event: {str(e)}")
        return jsonify({'message': 'Failed to delete event', 'error': str(e)}), 500

@app.route('/api/calendar/event-types', methods=['GET'])
@token_required
def get_event_types(current_user):
    """Get available event types"""
    return jsonify({
        'eventTypes': [
            {'value': 'meeting', 'label': 'Meeting', 'color': 'purple'},
            {'value': 'deadline', 'label': 'Deadline', 'color': 'rose'},
            {'value': 'work', 'label': 'Work Session', 'color': 'blue'},
            {'value': 'review', 'label': 'Review', 'color': 'green'},
            {'value': 'milestone', 'label': 'Milestone', 'color': 'amber'},
            {'value': 'other', 'label': 'Other', 'color': 'slate'}
        ]
    }), 200

# ============================================
# ERROR HANDLERS
# ============================================
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'message': 'Rate limit exceeded'}), 429

@app.errorhandler(404)
def not_found(e):
    return jsonify({'message': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'message': 'Internal server error'}), 500

# ============================================
# STARTUP
# ============================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(debug=True, host='0.0.0.0', port=8000, threaded=False)