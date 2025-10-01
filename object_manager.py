"""
Object Manager for Mandatory Access Control System
Provides high-level interface for object operations with security enforcement
"""
from database import get_db_connection
from access_manager import AccessManager
from security_monitor import SecurityMonitor
from audit import log_event

class ObjectManager:
    """
    High-level object management with integrated security checks
    Provides simplified interface for object operations
    """
    
    def __init__(self):
        self.access_manager = AccessManager()
        self.security_monitor = SecurityMonitor()
    
    def create_object(self, user_id, object_name, content, security_level):
        """
        Create a new object with security level validation
        Returns success status and object ID if created
        """
        # Validate security level
        if not self.security_monitor.validate_security_level(security_level):
            return False, "Invalid security level"
        
        # Use access manager to create object
        success = self.access_manager.request_object_creation(
            user_id, object_name, content, security_level
        )
        
        if success:
            return True, "Object created successfully"
        else:
            return False, "Failed to create object - check permissions"
    
    def read_object(self, user_id, object_id):
        """
        Read object content with access control
        Returns object data if access granted, None if denied
        """
        result = self.access_manager.request_read_access(user_id, object_id)
        
        if result:
            object_name, content = result
            return {
                'name': object_name,
                'content': content,
                'access': 'granted'
            }
        else:
            return {
                'access': 'denied',
                'message': 'Read access denied or object not found'
            }
    
    def update_object(self, user_id, object_id, new_content):
        """
        Update object content with write access control
        Returns success status and message
        """
        success = self.access_manager.request_write_access(user_id, object_id, new_content)
        
        if success:
            return True, "Object updated successfully"
        else:
            return False, "Write access denied or object not found"
    
    def delete_object(self, user_id, object_id):
        """
        Delete object with proper access control
        Only owner or Top Secret super admin can delete
        """
        success = self.access_manager.request_object_deletion(user_id, object_id)
        
        if success:
            return True, "Object deleted successfully"
        else:
            return False, "Delete access denied or object not found"
    
    def list_user_objects(self, user_id):
        """
        Get all objects accessible to the user
        Returns filtered list based on user's security level
        """
        objects = self.access_manager.get_accessible_objects(user_id)
        
        formatted_objects = []
        for obj in objects:
            formatted_objects.append({
                'id': obj['id'],
                'name': obj['name'],
                'security_level': obj['security_level'],
                'owner_id': obj['owner_id']
            })
        
        return formatted_objects
    
    def get_object_info(self, user_id, object_id):
        """
        Get object metadata without content
        Useful for displaying object lists with security info
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get object details
        cursor.execute("""
            SELECT name, security_level, owner_id, created_at 
            FROM objects WHERE id = ?
        """, (object_id,))
        
        obj = cursor.fetchone()
        conn.close()
        
        if not obj:
            return None
        
        # Check if user can view this object
        user_level = self._get_user_security_level(user_id)
        if not self.security_monitor.can_view_object_existence(user_level, obj['security_level']):
            return None
        
        return {
            'name': obj['name'],
            'security_level': obj['security_level'],
            'owner_id': obj['owner_id'],
            'created_at': obj['created_at']
        }
    
    def search_objects(self, user_id, search_term=""):
        """
        Search objects by name (within user's access level)
        Returns matching objects user has permission to see
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user security level first
        user_level = self._get_user_security_level(user_id)
        
        # Search objects that match name and are within user's level
        cursor.execute("""
            SELECT id, name, security_level, owner_id 
            FROM objects 
            WHERE name LIKE ? AND security_level <= ?
            ORDER BY security_level DESC, name ASC
        """, (f"%{search_term}%", user_level))
        
        objects = cursor.fetchall()
        conn.close()
        
        formatted_objects = []
        for obj in objects:
            formatted_objects.append({
                'id': obj['id'],
                'name': obj['name'],
                'security_level': obj['security_level'],
                'owner_id': obj['owner_id']
            })
        
        return formatted_objects
    
    def _get_user_security_level(self, user_id):
        """Helper method to get user's security level"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT security_level FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        return user['security_level'] if user else 0
    
    def get_objects_by_level(self, user_id, security_level):
        """
        Get objects filtered by specific security level
        Only returns objects at or below user's level
        """
        user_level = self._get_user_security_level(user_id)
        
        if security_level > user_level:
            return []  # User cannot see objects at this level
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, name, owner_id 
            FROM objects 
            WHERE security_level = ?
            ORDER BY name ASC
        """, (security_level,))
        
        objects = cursor.fetchall()
        conn.close()
        
        return [dict(obj) for obj in objects]