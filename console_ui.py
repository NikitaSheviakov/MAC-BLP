"""
Console User Interface for Mandatory Access Control System
Provides command-line interface for user interactions
"""
from tabulate import tabulate
from config import SECURITY_LEVELS
from object_manager import ObjectManager
from user_manager import UserManager
from audit import get_audit_logs, get_audit_statistics

class ConsoleUI:
    """
    Command-line interface for the MAC system
    Handles user input and displays system responses
    """
    
    def __init__(self):
        self.object_manager = ObjectManager()
        self.user_manager = UserManager()
        self.current_user = None
    
    def display_welcome(self):
        """Display welcome message and system information"""
        print("\n" + "="*60)
        print("    MANDATORY ACCESS CONTROL SYSTEM - BELL-LAPADULA MODEL")
        print("="*60)
        print("Security Levels: 0=Public, 1=Confidential, 2=Secret, 3=Top Secret")
        print("Type 'help' for available commands")
        print("="*60)
    
    def display_help(self):
        """Display available commands and their descriptions"""
        help_text = """
Available Commands:

AUTHENTICATION:
  register     - Register a new user
  login        - Login to system
  logout       - Logout current user
  whoami       - Show current user information

OBJECT OPERATIONS:
  create_obj   - Create a new object with security level
  list_obj     - List accessible objects
  read_obj     - Read object content
  write_obj    - Update object content
  delete_obj   - Delete an object
  search_obj   - Search objects by name

USER MANAGEMENT (Admin):
  list_users   - List all users (Top Secret required)
  user_info    - View user information
  change_level - Change user security level (Super Admin only)
  deactivate   - Deactivate user account (Super Admin only)
  activate     - Activate user account (Super Admin only)

AUDIT & SYSTEM:
  show_audit   - Display audit logs
  filter_audit - Filter audit logs by criteria
  stats        - System statistics (Top Secret required)
  help         - Show this help message
  exit         - Exit system

Security Rules:
  - Read: Your level must be >= object level
  - Write: Your level must be <= object level  
  - Delete: Owner or Top Secret Super Admin only
"""
        print(help_text)
    
    def get_user_input(self, prompt):
        """Get input from user with current user context"""
        if self.current_user:
            username = self.current_user['username']
            level_name = SECURITY_LEVELS.get(self.current_user['security_level'], 'Unknown')
            user_prompt = f"{username}({level_name})> "
        else:
            user_prompt = "system> "
        
        return input(user_prompt + prompt).strip()
    
    def handle_register(self):
        """Handle user registration"""
        username = self.get_user_input("Enter username: ")
        password = self.get_user_input("Enter password: ")
        
        from auth import register_user
        success = register_user(username, password)
        
        if success:
            print("Registration successful")
        else:
            print("Registration failed - username may already exist")
    
    def handle_login(self):
        """Handle user login"""
        if self.current_user:
            print("You are already logged in. Please logout first.")
            return
        
        username = self.get_user_input("Enter username: ")
        password = self.get_user_input("Enter password: ")
        
        from auth import login_user
        user_data = login_user(username, password)
        
        if user_data:
            user_id, username, security_level, is_super_admin = user_data
            self.current_user = {
                'id': user_id,
                'username': username,
                'security_level': security_level,
                'is_super_admin': is_super_admin
            }
            print(f"Login successful. Welcome {username}!")
            print(f"Security Level: {SECURITY_LEVELS[security_level]}")
            if is_super_admin:
                print("Privileges: Super Administrator")
        else:
            print("Login failed - invalid credentials")
    
    def handle_logout(self):
        """Handle user logout"""
        if self.current_user:
            print(f"User '{self.current_user['username']}' logged out.")
            self.current_user = None
        else:
            print("No user is currently logged in.")
    
    def handle_whoami(self):
        """Display current user information"""
        if not self.current_user:
            print("Not logged in")
            return
        
        user_info, error = self.user_manager.get_user_info(self.current_user['id'])
        
        if error:
            print(f"Error: {error}")
            return
        
        print("\nCurrent User Information:")
        print(f"Username: {user_info['username']}")
        print(f"Security Level: {user_info['security_level_name']}")
        print(f"Super Admin: {user_info['is_super_admin']}")
        print(f"Active: {user_info['is_active']}")
        print(f"User ID: {user_info['id']}")
        print(f"Registered: {user_info['created_at']}")
    
    def handle_create_object(self):
        """Handle object creation"""
        if not self.current_user:
            print("Error: You must be logged in to create objects")
            return
        
        name = self.get_user_input("Enter object name: ")
        content = self.get_user_input("Enter object content: ")
        
        print("Available security levels:")
        for level, desc in SECURITY_LEVELS.items():
            print(f"  {level}: {desc}")
        
        try:
            level_input = self.get_user_input("Enter security level (0-3): ")
            security_level = int(level_input)
            
            if security_level not in SECURITY_LEVELS:
                print("Error: Invalid security level")
                return
            
            success, message = self.object_manager.create_object(
                self.current_user['id'], name, content, security_level
            )
            
            if success:
                print(f"Success: {message}")
            else:
                print(f"Error: {message}")
                
        except ValueError:
            print("Error: Please enter a valid number")
    
    def handle_list_objects(self):
        """List accessible objects"""
        if not self.current_user:
            print("Error: You must be logged in to list objects")
            return
        
        objects = self.object_manager.list_user_objects(self.current_user['id'])
        
        if not objects:
            print("No accessible objects found")
            return
        
        # Format objects for display
        table_data = []
        for obj in objects:
            table_data.append([
                obj['id'],
                obj['name'],
                SECURITY_LEVELS.get(obj['security_level'], 'Unknown'),
                obj['owner_id']
            ])
        
        headers = ["ID", "Name", "Security Level", "Owner ID"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nTotal objects: {len(objects)}")
    
    def handle_read_object(self):
        """Read object content"""
        if not self.current_user:
            print("Error: You must be logged in to read objects")
            return
        
        try:
            obj_id = int(self.get_user_input("Enter object ID: "))
        except ValueError:
            print("Error: Please enter a valid object ID")
            return
        
        result = self.object_manager.read_object(self.current_user['id'], obj_id)
        
        if result['access'] == 'granted':
            print(f"\nObject: {result['name']}")
            print(f"Content: {result['content']}")
        else:
            print(f"Error: {result['message']}")
    
    def handle_write_object(self):
        """Update object content"""
        if not self.current_user:
            print("Error: You must be logged in to write objects")
            return
        
        try:
            obj_id = int(self.get_user_input("Enter object ID: "))
            new_content = self.get_user_input("Enter new content: ")
        except ValueError:
            print("Error: Please enter a valid object ID")
            return
        
        success, message = self.object_manager.update_object(
            self.current_user['id'], obj_id, new_content
        )
        
        if success:
            print(f"Success: {message}")
        else:
            print(f"Error: {message}")
    
    def handle_delete_object(self):
        """Delete an object"""
        if not self.current_user:
            print("Error: You must be logged in to delete objects")
            return
        
        try:
            obj_id = int(self.get_user_input("Enter object ID to delete: "))
        except ValueError:
            print("Error: Please enter a valid object ID")
            return
        
        # Confirm deletion
        confirm = self.get_user_input("Are you sure you want to delete this object? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Deletion cancelled")
            return
        
        success, message = self.object_manager.delete_object(self.current_user['id'], obj_id)
        
        if success:
            print(f"Success: {message}")
        else:
            print(f"Error: {message}")
    
    def handle_search_objects(self):
        """Search objects by name"""
        if not self.current_user:
            print("Error: You must be logged in to search objects")
            return
        
        search_term = self.get_user_input("Enter search term: ")
        objects = self.object_manager.search_objects(self.current_user['id'], search_term)
        
        if not objects:
            print("No matching objects found")
            return
        
        table_data = []
        for obj in objects:
            table_data.append([
                obj['id'],
                obj['name'],
                SECURITY_LEVELS.get(obj['security_level'], 'Unknown'),
                obj['owner_id']
            ])
        
        headers = ["ID", "Name", "Security Level", "Owner ID"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nFound {len(objects)} matching objects")
    
    def handle_list_users(self):
        """List all users (admin only)"""
        if not self.current_user:
            print("Error: You must be logged in")
            return
        
        users, error = self.user_manager.list_all_users(self.current_user['id'])
        
        if error:
            print(f"Error: {error}")
            return
        
        if not users:
            print("No users found")
            return
        
        table_data = []
        for user in users:
            table_data.append([
                user['id'],
                user['username'],
                user['security_level_name'],
                "Yes" if user['is_super_admin'] else "No",
                "Yes" if user['is_active'] else "No",
                user['created_at']
            ])
        
        headers = ["ID", "Username", "Security Level", "Super Admin", "Active", "Created"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nTotal users: {len(users)}")
    
    def handle_user_info(self):
        """Display user information"""
        if not self.current_user:
            print("Error: You must be logged in")
            return
        
        target_input = self.get_user_input("Enter user ID (or leave blank for your info): ")
        
        if target_input.strip() == "":
            target_id = None
        else:
            try:
                target_id = int(target_input)
            except ValueError:
                print("Error: Please enter a valid user ID")
                return
        
        user_info, error = self.user_manager.get_user_info(self.current_user['id'], target_id)
        
        if error:
            print(f"Error: {error}")
            return
        
        print("\nUser Information:")
        for key, value in user_info.items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
    
    def handle_change_level(self):
        """Change user security level (super admin only)"""
        if not self.current_user:
            print("Error: You must be logged in")
            return
        
        try:
            target_id = int(self.get_user_input("Enter target user ID: "))
            new_level = int(self.get_user_input("Enter new security level (0-3): "))
        except ValueError:
            print("Error: Please enter valid numbers")
            return
        
        success, message = self.user_manager.change_user_level(
            self.current_user['id'], target_id, new_level
        )
        
        if success:
            print(f"Success: {message}")
        else:
            print(f"Error: {message}")
    
    def handle_show_audit(self):
        """Display recent audit logs"""
        logs = get_audit_logs(limit=20)
        
        if not logs:
            print("No audit logs found")
            return
        
        table_data = []
        for log in logs:
            table_data.append([
                log['id'],
                log['timestamp'],
                log['username'] or 'Unknown',
                log['event_type'],
                log['object_name'] or '',
                log['details'],
                "SUCCESS" if log['success'] else "FAILED"
            ])
        
        headers = ["ID", "Timestamp", "User", "Event", "Object", "Details", "Result"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nShowing {len(logs)} most recent events")
    
    def handle_filter_audit(self):
        """Filter audit logs by criteria"""
        print("\nFilter options:")
        print("1 - Success events only")
        print("2 - Failed events only")
        print("3 - Login events")
        print("4 - Object access events")
        print("5 - Object modification events")
        
        choice = self.get_user_input("Select filter (or Enter for all): ")
        
        filters = {}
        if choice == "1":
            filters['success'] = True
        elif choice == "2":
            filters['success'] = False
        elif choice == "3":
            filters['event_type'] = 'user_login'
        elif choice == "4":
            filters['event_type'] = 'read_access'
        elif choice == "5":
            filters['event_type'] = 'write_access'
        
        logs = get_audit_logs(limit=30, filters=filters)
        
        if not logs:
            print("No matching audit logs found")
            return
        
        table_data = []
        for log in logs:
            table_data.append([
                log['id'],
                log['timestamp'],
                log['username'] or 'Unknown',
                log['event_type'],
                log['object_name'] or '',
                log['details'],
                "SUCCESS" if log['success'] else "FAILED"
            ])
        
        headers = ["ID", "Timestamp", "User", "Event", "Object", "Details", "Result"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nFound {len(logs)} matching events")
    
    def handle_stats(self):
        """Display system statistics"""
        if not self.current_user:
            print("Error: You must be logged in")
            return
        
        stats, error = self.user_manager.get_system_statistics(self.current_user['id'])
        
        if error:
            print(f"Error: {error}")
            return
        
        audit_stats = get_audit_statistics()
        
        print("\nSYSTEM STATISTICS")
        print("="*50)
        
        print("\nUSERS:")
        print(f"  Total Users: {stats['users']['total']}")
        print(f"  Active Users: {stats['users']['active']}")
        print(f"  Super Admins: {stats['users']['super_admins']}")
        
        print("\nOBJECTS:")
        print(f"  Total Objects: {stats['objects']['total']}")
        for level_name, count in stats['objects']['by_level'].items():
            print(f"  {level_name}: {count}")
        
        print("\nAUDIT:")
        print(f"  Total Events: {audit_stats['total_events']}")
        print(f"  Successful: {audit_stats['success_events']}")
        print(f"  Failed: {audit_stats['failed_events']}")
        
        print("\nEVENT TYPES:")
        for event_type, count in audit_stats['events_by_type']:
            print(f"  {event_type}: {count}")
    
    def run(self):
        """Main application loop"""
        self.display_welcome()
        
        while True:
            try:
                command = self.get_user_input("").lower().strip()
                
                if command == "":
                    continue
                elif command == "help":
                    self.display_help()
                elif command == "register":
                    self.handle_register()
                elif command == "login":
                    self.handle_login()
                elif command == "logout":
                    self.handle_logout()
                elif command == "whoami":
                    self.handle_whoami()
                elif command == "create_obj":
                    self.handle_create_object()
                elif command == "list_obj":
                    self.handle_list_objects()
                elif command == "read_obj":
                    self.handle_read_object()
                elif command == "write_obj":
                    self.handle_write_object()
                elif command == "delete_obj":
                    self.handle_delete_object()
                elif command == "search_obj":
                    self.handle_search_objects()
                elif command == "list_users":
                    self.handle_list_users()
                elif command == "user_info":
                    self.handle_user_info()
                elif command == "change_level":
                    self.handle_change_level()
                elif command == "show_audit":
                    self.handle_show_audit()
                elif command == "filter_audit":
                    self.handle_filter_audit()
                elif command == "stats":
                    self.handle_stats()
                elif command == "exit":
                    print("Exiting Mandatory Access Control System. Goodbye!")
                    break
                else:
                    print("Unknown command. Type 'help' for available commands.")
            
            except KeyboardInterrupt:
                print("\n\nExiting system. Goodbye!")
                break
            except Exception as e:
                print(f"System error: {e}")