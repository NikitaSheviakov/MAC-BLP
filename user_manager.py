"""
User Manager for Mandatory Access Control System
Handles user management operations with admin privileges
"""
from database import get_db_connection
from auth import change_user_security_level
from audit import log_event
from config import SECURITY_LEVELS

class UserManager:
    """
    User management system with administrative functions
    Requires appropriate privilege levels for operations
    """
    
    def __init__(self):
        pass
    
    def list_all_users(self, requester_id):
        """
        List all users in the system
        Only accessible to Top Secret users
        """
        # Verify requester has sufficient privileges
        if not self._is_top_secret_user(requester_id):
            return None, "Insufficient privileges - Top Secret level required"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, security_level, is_super_admin, is_active, created_at 
            FROM users 
            ORDER BY security_level DESC, username ASC
        """)
        
        users = cursor.fetchall()
        conn.close()
        
        formatted_users = []
        for user in users:
            formatted_users.append({
                'id': user['id'],
                'username': user['username'],
                'security_level': user['security_level'],
                'security_level_name': SECURITY_LEVELS.get(user['security_level'], 'Unknown'),
                'is_super_admin': bool(user['is_super_admin']),
                'is_active': bool(user['is_active']),
                'created_at': user['created_at']
            })
        
        log_event(requester_id, "list_users", details=f"Listed {len(formatted_users)} users", success=True)
        return formatted_users, None
    
    def change_user_level(self, requester_id, target_user_id, new_level):
        """
        Change another user's security level
        Only accessible to super admin users
        """
        # Verify requester is super admin
        if not self._is_super_admin(requester_id):
            return False, "Only super admin can change security levels"
        
        # Validate security level
        if new_level not in SECURITY_LEVELS:
            return False, f"Invalid security level. Must be one of: {list(SECURITY_LEVELS.keys())}"
        
        # Get target user info for logging
        target_username = self._get_username(target_user_id)
        if not target_username:
            return False, "Target user not found"
        
        # Use auth module to change level
        success = change_user_security_level(target_user_id, new_level, True)
        
        if success:
            log_event(requester_id, "change_user_level", 
                     details=f"Changed {target_username} to level {new_level}", success=True)
            return True, f"Security level for {target_username} changed to {SECURITY_LEVELS[new_level]}"
        else:
            log_event(requester_id, "change_user_level", 
                     details=f"Failed to change {target_username} to level {new_level}", success=False)
            return False, "Failed to change security level"
    
    def deactivate_user(self, requester_id, target_user_id):
        """
        Deactivate a user account
        Only accessible to super admin users
        """
        if not self._is_super_admin(requester_id):
            return False, "Only super admin can deactivate users"
        
        target_username = self._get_username(target_user_id)
        if not target_username:
            return False, "Target user not found"
        
        # Cannot deactivate yourself
        if requester_id == target_user_id:
            return False, "Cannot deactivate your own account"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (target_user_id,))
            conn.commit()
            log_event(requester_id, "deactivate_user", 
                     details=f"Deactivated user: {target_username}", success=True)
            conn.close()
            return True, f"User {target_username} deactivated successfully"
        except Exception as e:
            log_event(requester_id, "deactivate_user", 
                     details=f"Failed to deactivate {target_username}: {e}", success=False)
            conn.close()
            return False, f"Error deactivating user: {e}"
    
    def activate_user(self, requester_id, target_user_id):
        """
        Activate a deactivated user account
        Only accessible to super admin users
        """
        if not self._is_super_admin(requester_id):
            return False, "Only super admin can activate users"
        
        target_username = self._get_username(target_user_id)
        if not target_username:
            return False, "Target user not found"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("UPDATE users SET is_active = 1 WHERE id = ?", (target_user_id,))
            conn.commit()
            log_event(requester_id, "activate_user", 
                     details=f"Activated user: {target_username}", success=True)
            conn.close()
            return True, f"User {target_username} activated successfully"
        except Exception as e:
            log_event(requester_id, "activate_user", 
                     details=f"Failed to activate {target_username}: {e}", success=False)
            conn.close()
            return False, f"Error activating user: {e}"
    
    def get_user_info(self, requester_id, target_user_id=None):
        """
        Get user information
        Users can view their own info, admins can view any user's info
        """
        if target_user_id is None:
            target_user_id = requester_id  # View own profile
        
        # Check permissions
        if target_user_id != requester_id and not self._is_top_secret_user(requester_id):
            return None, "Insufficient privileges to view other users"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, security_level, is_super_admin, is_active, created_at 
            FROM users WHERE id = ?
        """, (target_user_id,))
        
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return None, "User not found"
        
        user_info = {
            'id': user['id'],
            'username': user['username'],
            'security_level': user['security_level'],
            'security_level_name': SECURITY_LEVELS.get(user['security_level'], 'Unknown'),
            'is_super_admin': bool(user['is_super_admin']),
            'is_active': bool(user['is_active']),
            'created_at': user['created_at']
        }
        
        log_event(requester_id, "view_user_info", 
                 details=f"Viewed info for user ID: {target_user_id}", success=True)
        return user_info, None
    
    def get_system_statistics(self, requester_id):
        """
        Get system statistics (user counts, object counts by level)
        Only accessible to Top Secret users
        """
        if not self._is_top_secret_user(requester_id):
            return None, "Insufficient privileges - Top Secret level required"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # User statistics
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        active_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_super_admin = 1")
        super_admins = cursor.fetchone()[0]
        
        # Object statistics by security level
        object_stats = {}
        for level in SECURITY_LEVELS.keys():
            cursor.execute("SELECT COUNT(*) FROM objects WHERE security_level = ?", (level,))
            count = cursor.fetchone()[0]
            object_stats[SECURITY_LEVELS[level]] = count
        
        cursor.execute("SELECT COUNT(*) FROM objects")
        total_objects = cursor.fetchone()[0]
        
        conn.close()
        
        statistics = {
            'users': {
                'total': total_users,
                'active': active_users,
                'super_admins': super_admins
            },
            'objects': {
                'total': total_objects,
                'by_level': object_stats
            }
        }
        
        log_event(requester_id, "view_statistics", details="Viewed system statistics", success=True)
        return statistics, None
    
    def _is_super_admin(self, user_id):
        """Check if user is super admin"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT is_super_admin FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user and user['is_super_admin']
    
    def _is_top_secret_user(self, user_id):
        """Check if user has Top Secret level"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT security_level FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user and user['security_level'] == 3
    
    def _get_username(self, user_id):
        """Get username by user ID"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user['username'] if user else None