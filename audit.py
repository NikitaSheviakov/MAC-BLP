"""
Audit system for logging security events
Extended version with filtering capabilities
"""
import sqlite3
from database import get_db_connection

def log_event(user_id, event_type, object_id=None, details="", success=True):
    """
    Log security event to audit database
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO audit_logs (event_type, user_id, object_id, details, success) 
            VALUES (?, ?, ?, ?, ?)
        """, (event_type, user_id, object_id, details, success))
        conn.commit()
    except Exception as e:
        print(f"Audit logging error: {e}")
    finally:
        conn.close()

def get_audit_logs(limit=50, filters=None):
    """
    Retrieve audit logs with optional filtering
    Returns formatted list of audit records
    """
    if filters is None:
        filters = {}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Build query with filters
    query = """
        SELECT al.id, al.timestamp, al.event_type, al.details, al.success,
               u.username, o.name as object_name
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        LEFT JOIN objects o ON al.object_id = o.id
        WHERE 1=1
    """
    params = []
    
    # Apply filters
    if filters.get('event_type'):
        query += " AND al.event_type = ?"
        params.append(filters['event_type'])
    
    if filters.get('success') is not None:
        query += " AND al.success = ?"
        params.append(filters['success'])
    
    if filters.get('user_id'):
        query += " AND al.user_id = ?"
        params.append(filters['user_id'])
    
    # Add ordering and limit
    query += " ORDER BY al.timestamp DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    logs = cursor.fetchall()
    conn.close()
    
    return logs

def get_audit_statistics():
    """
    Get statistics about audit events
    Useful for security analysis
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get total events count
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    total_events = cursor.fetchone()[0]
    
    # Get success/failure count
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE success = 1")
    success_events = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE success = 0")
    failed_events = cursor.fetchone()[0]
    
    # Get events by type
    cursor.execute("""
        SELECT event_type, COUNT(*) as count 
        FROM audit_logs 
        GROUP BY event_type 
        ORDER BY count DESC
    """)
    events_by_type = cursor.fetchall()
    
    conn.close()
    
    return {
        'total_events': total_events,
        'success_events': success_events,
        'failed_events': failed_events,
        'events_by_type': events_by_type
    }