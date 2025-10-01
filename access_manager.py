"""
Access Manager - Centralized access control system
Coordinates between security monitor and database operations
"""
import sqlite3
from security_monitor import SecurityMonitor
from database import get_db_connection
from audit import log_event

class AccessManager:
    """
    Centralized access control manager
    Handles all object access requests and enforces security policy
    """
    
    def __init__(self):
        self.security_monitor = SecurityMonitor()
    
    def request_read_access(self, user_id, object_id):
        """
        Handle read access request for an object
        Returns object content if access granted, None if denied
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user and object security levels
        cursor.execute("SELECT security_level FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        
        cursor.execute("SELECT name, content, security_level, owner_id FROM objects WHERE id = ?", (object_id,))
        object_row = cursor.fetchone()
        
        if not user_row or not object_row:
            conn.close()
            log_event(user_id, "read_access", object_id, "User or object not found", False)
            return None
        
        user_level = user_row['security_level']
        object_name, content, object_level, owner_id = object_row
        
        # Check if user can even see the object exists
        if not self.security_monitor.can_view_object_existence(user_level, object_level):
            conn.close()
            log_event(user_id, "read_access", object_id, 
                     f"Cannot view object existence - User level: {user_level}, Object level: {object_level}", False)
            return None
        
        # Check read access using security monitor
        if self.security_monitor.check_read_access(user_level, object_level):
            access_description = self.security_monitor.get_access_description(user_level, object_level, "read")
            log_event(user_id, "read_access", object_id, access_description, True)
            conn.close()
            return (object_name, content)
        else:
            access_description = self.security_monitor.get_access_description(user_level, object_level, "read")
            log_event(user_id, "read_access", object_id, access_description, False)
            conn.close()
            return None
    
    def request_write_access(self, user_id, object_id, new_content):
        """
        Handle write access request for an object
        Returns True if access granted and write successful, False otherwise
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user and object security levels
        cursor.execute("SELECT security_level FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        
        cursor.execute("SELECT security_level, owner_id FROM objects WHERE id = ?", (object_id,))
        object_row = cursor.fetchone()
        
        if not user_row or not object_row:
            conn.close()
            log_event(user_id, "write_access", object_id, "User or object not found", False)
            return False
        
        user_level = user_row['security_level']
        object_level, owner_id = object_row
        
        # Check write access using security monitor
        if self.security_monitor.check_write_access(user_level, object_level):
            try:
                cursor.execute("UPDATE objects SET content = ? WHERE id = ?", (new_content, object_id))
                conn.commit()
                access_description = self.security_monitor.get_access_description(user_level, object_level, "write")
                log_event(user_id, "write_access", object_id, access_description, True)
                conn.close()
                return True
            except Exception as e:
                log_event(user_id, "write_access", object_id, f"Database error: {e}", False)
                conn.close()
                return False
        else:
            access_description = self.security_monitor.get_access_description(user_level, object_level, "write")
            log_event(user_id, "write_access", object_id, access_description, False)
            conn.close()
            return False
    
    def request_object_creation(self, user_id, object_name, content, security_level):
        """
        Handle object creation request
        Users can create objects at their own security level or lower
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user security level
        cursor.execute("SELECT security_level, is_super_admin FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        
        if not user_row:
            conn.close()
            log_event(user_id, "create_object", None, "User not found", False)
            return False
        
        user_level = user_row['security_level']
        
        # Validate requested security level
        if not self.security_monitor.validate_security_level(security_level):
            log_event(user_id, "create_object", None, f"Invalid security level: {security_level}", False)
            conn.close()
            return False
        
        # Users can only create objects at or below their own level
        # Super admins can create objects at any level
        if user_row['is_super_admin'] or security_level <= user_level:
            try:
                cursor.execute(
                    "INSERT INTO objects (name, content, security_level, owner_id) VALUES (?, ?, ?, ?)",
                    (object_name, content, security_level, user_id)
                )
                conn.commit()
                object_id = cursor.lastrowid
                log_event(user_id, "create_object", object_id, 
                         f"Object created with level: {security_level}", True)
                conn.close()
                return True
            except Exception as e:
                log_event(user_id, "create_object", None, f"Database error: {e}", False)
                conn.close()
                return False
        else:
            log_event(user_id, "create_object", None, 
                     f"Cannot create object at level {security_level} (user level: {user_level})", False)
            conn.close()
            return False
    
    def request_object_deletion(self, user_id, object_id):
        """
        Handle object deletion request
        Only owner or Top Secret super admin can delete objects
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user info
        cursor.execute("SELECT security_level, is_super_admin FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        
        cursor.execute("SELECT security_level, owner_id FROM objects WHERE id = ?", (object_id,))
        object_row = cursor.fetchone()
        
        if not user_row or not object_row:
            conn.close()
            log_event(user_id, "delete_object", object_id, "User or object not found", False)
            return False
        
        user_level = user_row['security_level']
        is_super_admin = user_row['is_super_admin']
        object_level, owner_id = object_row
        is_owner = (user_id == owner_id)
        
        # Check delete access using security monitor
        if self.security_monitor.check_delete_access(user_level, object_level, is_owner, is_super_admin):
            try:
                cursor.execute("DELETE FROM objects WHERE id = ?", (object_id,))
                conn.commit()
                log_event(user_id, "delete_object", object_id, "Object deleted successfully", True)
                conn.close()
                return True
            except Exception as e:
                log_event(user_id, "delete_object", object_id, f"Database error: {e}", False)
                conn.close()
                return False
        else:
            log_event(user_id, "delete_object", object_id, 
                     f"Delete access denied - Owner: {is_owner}, Super Admin: {is_super_admin}", False)
            conn.close()
            return False
    
    def get_accessible_objects(self, user_id):
        """
        Get list of objects accessible to the user (based on security level)
        Returns only objects that user has permission to see
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user security level
        cursor.execute("SELECT security_level FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        
        if not user_row:
            conn.close()
            return []
        
        user_level = user_row['security_level']
        
        # Get all objects that user can see (based on security level)
        cursor.execute("""
            SELECT id, name, security_level, owner_id 
            FROM objects 
            WHERE security_level <= ?
            ORDER BY security_level DESC, name ASC
        """, (user_level,))
        
        objects = cursor.fetchall()
        conn.close()
        
        return objects