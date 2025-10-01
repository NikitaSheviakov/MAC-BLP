"""
Authentication module for Mandatory Access Control System
Handles user registration and login with bcrypt password hashing
"""
import hashlib
from database import get_db_connection

def register_user(username, password):
    """
    Register a new user in the system
    First user becomes super admin, others get Public level by default
    Returns True on success, False on failure
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if username already exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        print("Error: Username already exists")
        conn.close()
        return False
    
    # Hash password using SHA-256 (simple hashing for now)
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Determine if this is the first user (super admin)
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    
    if user_count == 0:
        # First user becomes super admin with Top Secret level
        security_level = 3
        is_super_admin = 1
    else:
        # Regular users get Public level by default
        security_level = 0
        is_super_admin = 0
    
    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash, security_level, is_super_admin) 
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, security_level, is_super_admin))
        
        conn.commit()
        conn.close()
        
        if is_super_admin:
            print("Super admin user registered successfully")
        else:
            print("User registered successfully")
        return True
        
    except Exception as e:
        print(f"Registration error: {e}")
        conn.close()
        return False

def login_user(username, password):
    """
    Authenticate user with username and password
    Returns user data tuple (id, username, security_level, is_super_admin) on success
    Returns None on failure
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Find user by username
    cursor.execute("""
        SELECT id, username, password_hash, security_level, is_super_admin 
        FROM users 
        WHERE username = ? AND is_active = 1
    """, (username,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        print("Error: User not found or inactive")
        return None
    
    # Verify password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user['password_hash'] == password_hash:
        user_data = (
            user['id'],
            user['username'], 
            user['security_level'],
            bool(user['is_super_admin'])
        )
        return user_data
    else:
        print("Error: Invalid password")
        return None

def change_user_security_level(target_user_id, new_level, requester_is_super_admin):
    """
    Change user security level (super admin only)
    Returns True on success, False on failure
    """
    if not requester_is_super_admin:
        print("Error: Only super admin can change security levels")
        return False
    
    if new_level not in [0, 1, 2, 3]:
        print("Error: Invalid security level")
        return False
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE users 
            SET security_level = ? 
            WHERE id = ?
        """, (new_level, target_user_id))
        
        conn.commit()
        conn.close()
        print("User security level updated successfully")
        return True
        
    except Exception as e:
        print(f"Error updating security level: {e}")
        conn.close()
        return False