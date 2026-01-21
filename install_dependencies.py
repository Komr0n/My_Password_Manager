#!/usr/bin/env python3
"""
Install dependencies for Password Manager
"""

import subprocess
import sys
import os

def install_dependencies():
    """Install required packages"""
    print("Installing dependencies for Password Manager...")
    
    # List of required packages
    packages = [
        "pycryptodome>=3.19.0",
        "pyperclip>=1.8.2"
    ]
    
    for package in packages:
        print(f"Installing {package}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"OK: Successfully installed {package}")
        except subprocess.CalledProcessError as e:
            print(f"FAIL: Failed to install {package}: {e}")
            return False
    
    print("\nAll dependencies installed successfully!")
    print("You can now run the password manager with: python password_manager.py")
    return True

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("Error: Python 3.7 or higher is required!")
        print(f"Current version: {sys.version}")
        return False
    return True

def main():
    """Main function"""
    print("Password Manager - Dependency Installer")
    print("=" * 40)
    
    if not check_python_version():
        input("Press Enter to exit...")
        return
    
    if install_dependencies():
        print("\nSetup complete! You can now run the password manager.")
    else:
        print("\nSetup failed! Please check the error messages above.")
    
    input("Press Enter to exit...")

if __name__ == "__main__":
    main() 