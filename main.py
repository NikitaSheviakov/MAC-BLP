"""
Main entry point for Mandatory Access Control System
Bell-LaPadula Model Implementation
"""
from database import init_database
from console_ui import ConsoleUI

def main():
    """
    Main function - initializes system and starts user interface
    """
    try:
        # Initialize database and system
        print("Initializing Mandatory Access Control System...")
        init_database()
        
        # Start console interface
        ui = ConsoleUI()
        ui.run()
        
    except Exception as e:
        print(f"Fatal error during system startup: {e}")
        print("Please check system configuration and try again.")

if __name__ == "__main__":
    main()