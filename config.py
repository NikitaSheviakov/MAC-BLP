"""
Configuration file for Mandatory Access Control System
Defines security levels and system constants
"""

# Security levels configuration
SECURITY_LEVELS = {
    0: "Public",
    1: "Confidential", 
    2: "Secret",
    3: "Top Secret"
}

# Database configuration
DATABASE_NAME = "mandatory_access.db"

# System settings
MAX_LOGIN_ATTEMPTS = 3
SESSION_TIMEOUT = 3600  # 1 hour in seconds

# Audit event types
AUDIT_EVENTS = {
    "LOGIN": "user_login",
    "LOGOUT": "user_logout", 
    "REGISTER": "user_register",
    "CREATE_OBJECT": "object_create",
    "READ_OBJECT": "object_read",
    "WRITE_OBJECT": "object_write",
    "DELETE_OBJECT": "object_delete",
    "ACCESS_DENIED": "access_denied"
}