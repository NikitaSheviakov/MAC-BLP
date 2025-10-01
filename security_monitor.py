"""
Security Monitor for Bell-LaPadula Model
Implements mandatory access control rules
"""
from config import SECURITY_LEVELS

class SecurityMonitor:
    """
    Implements Bell-LaPadula mandatory access control rules:
    - No Read Up: User cannot read objects at higher classification levels
    - No Write Down: User cannot write to objects at lower classification levels
    """
    
    @staticmethod
    def check_read_access(user_level, object_level):
        """
        Check if user can read an object (Simple Security Property - No Read Up)
        User can read if their level >= object level
        """
        if user_level not in SECURITY_LEVELS or object_level not in SECURITY_LEVELS:
            return False
        
        return user_level >= object_level
    
    @staticmethod
    def check_write_access(user_level, object_level):
        """
        Check if user can write to an object (*-Property - No Write Down)
        User can write if their level <= object level
        """
        if user_level not in SECURITY_LEVELS or object_level not in SECURITY_LEVELS:
            return False
        
        return user_level <= object_level
    
    @staticmethod
    def check_delete_access(user_level, object_level, is_owner, is_super_admin):
        """
        Check if user can delete an object
        Owner can delete OR Top Secret admin can delete any object
        """
        if is_super_admin and user_level == 3:  # Top Secret super admin
            return True
        
        if is_owner and user_level == object_level:
            return True
        
        return False
    
    @staticmethod
    def can_view_object_existence(user_level, object_level):
        """
        Check if user can see that an object exists
        Users can only see objects at or below their security level
        """
        return user_level >= object_level
    
    @staticmethod
    def get_access_description(user_level, object_level, action):
        """
        Get detailed description of access check result
        Useful for audit logs and error messages
        """
        user_level_name = SECURITY_LEVELS.get(user_level, "Unknown")
        object_level_name = SECURITY_LEVELS.get(object_level, "Unknown")
        
        if action == "read":
            if user_level >= object_level:
                return f"READ granted: {user_level_name} can read {object_level_name}"
            else:
                return f"READ denied: {user_level_name} cannot read {object_level_name} (No Read Up)"
        
        elif action == "write":
            if user_level <= object_level:
                return f"WRITE granted: {user_level_name} can write to {object_level_name}"
            else:
                return f"WRITE denied: {user_level_name} cannot write to {object_level_name} (No Write Down)"
        
        return "Unknown action"

    @staticmethod
    def validate_security_level(level):
        """Validate if security level is within acceptable range"""
        return level in SECURITY_LEVELS