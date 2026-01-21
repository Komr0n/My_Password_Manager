#!/usr/bin/env python3
"""
Run Password Manager Application
"""

import sys
import os
import subprocess

def check_dependencies():
    """Check if required packages are installed"""
    try:
        import tkinter
        import Crypto
        import pyperclip
        return True
    except ImportError as e:
        print(f"Missing dependency: {e}")
        return False

def install_missing_dependencies():
    """Install missing dependencies"""
    print("Installing missing dependencies...")
    try:
        subprocess.check_call([sys.executable, "install_dependencies.py"])
        return True
    except subprocess.CalledProcessError:
        print("Failed to install dependencies automatically.")
        print("Please run: python install_dependencies.py")
        return False

def main():
    """Main function"""
    print("Password Manager - Launcher")
    print("=" * 30)
    
    # Check if dependencies are installed
    if not check_dependencies():
        print("Some dependencies are missing.")
        choice = input("Would you like to install them now? (y/n): ").lower()
        if choice in ['y', 'yes']:
            if not install_missing_dependencies():
                input("Press Enter to exit...")
                return
        else:
            print("Please install dependencies manually:")
            print("python install_dependencies.py")
            input("Press Enter to exit...")
            return
    
    # Check if main file exists
    main_file = "password_manager_improved.py"
    if not os.path.exists(main_file):
        main_file = "password_manager.py"
    if not os.path.exists(main_file):
        print("Error: password manager entrypoint not found!")
        input("Press Enter to exit...")
        return
    
    # Run the password manager
    print("Starting Password Manager...")
    try:
        subprocess.run([sys.executable, main_file])
    except KeyboardInterrupt:
        print("\nApplication interrupted by user.")
    except Exception as e:
        print(f"Error running password manager: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main() 
