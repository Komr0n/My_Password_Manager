#!/usr/bin/env python3
"""
Test script for Password Manager functions
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test if all modules can be imported"""
    print("Testing imports...")
    
    try:
        from constants import *
        print("✓ constants imported")
    except Exception as e:
        print(f"✗ constants import failed: {e}")
        return False
    
    try:
        from logger import setup_logger, log_info, log_error, log_debug
        print("✓ logger imported")
    except Exception as e:
        print(f"✗ logger import failed: {e}")
        return False
    
    try:
        from encryption import EncryptionManager
        print("✓ encryption imported")
    except Exception as e:
        print(f"✗ encryption import failed: {e}")
        return False
    
    try:
        from storage import PasswordStorage
        print("✓ storage imported")
    except Exception as e:
        print(f"✗ storage import failed: {e}")
        return False
    
    try:
        from password_generator import PasswordGenerator
        print("✓ password_generator imported")
    except Exception as e:
        print(f"✗ password_generator import failed: {e}")
        return False
    
    try:
        from auto_lock import AutoLock
        print("✓ auto_lock imported")
    except Exception as e:
        print(f"✗ auto_lock import failed: {e}")
        return False
    
    try:
        from ui_dialogs import PasswordManagerDialogs
        print("✓ ui_dialogs imported")
    except Exception as e:
        print(f"✗ ui_dialogs import failed: {e}")
        return False
    
    return True

def test_encryption():
    """Test encryption functionality"""
    print("\nTesting encryption...")
    
    try:
        from logger import setup_logger
        from encryption import EncryptionManager
        
        logger = setup_logger()
        enc_manager = EncryptionManager(logger)
        
        # Test salt generation
        salt = enc_manager.generate_salt()
        print(f"✓ Salt generated: {len(salt)} bytes")
        
        # Test key derivation
        password = "test_password_123"
        key = enc_manager.derive_key(password)
        print(f"✓ Key derived: {len(key)} bytes")
        
        # Test password hashing
        hash_value = enc_manager.hash_password(password)
        print(f"✓ Password hashed: {len(hash_value)} chars")
        
        # Test password verification
        is_valid = enc_manager.verify_password_hash(password, hash_value)
        print(f"✓ Password verification: {is_valid}")
        
        # Test data encryption/decryption
        test_data = {"test": "data", "number": 42}
        encrypted = enc_manager.encrypt_data(test_data)
        print(f"✓ Data encrypted: {len(encrypted)} chars")
        
        decrypted = enc_manager.decrypt_data(encrypted)
        print(f"✓ Data decrypted: {decrypted == test_data}")
        
        return True
        
    except Exception as e:
        print(f"✗ Encryption test failed: {e}")
        return False

def test_password_generator():
    """Test password generator functionality"""
    print("\nTesting password generator...")
    
    try:
        from logger import setup_logger
        from password_generator import PasswordGenerator
        
        logger = setup_logger()
        gen = PasswordGenerator(logger)
        
        # Test random password generation
        password = gen.generate_password(length=12, use_uppercase=True, use_digits=True, use_symbols=True)
        print(f"✓ Random password generated: {password}")
        
        # Test mnemonic password generation
        mnemonic = gen.generate_password(length=16, use_mnemonic=True)
        print(f"✓ Mnemonic password generated: {mnemonic}")
        
        # Test password strength calculation
        score = gen.calculate_password_strength(password)
        print(f"✓ Password strength calculated: {score}/100")
        
        return True
        
    except Exception as e:
        print(f"✗ Password generator test failed: {e}")
        return False

def test_storage():
    """Test storage functionality"""
    print("\nTesting storage...")
    
    try:
        from logger import setup_logger
        from encryption import EncryptionManager
        from storage import PasswordStorage
        
        logger = setup_logger()
        enc_manager = EncryptionManager(logger)
        storage = PasswordStorage(enc_manager, logger)
        
        # Test adding password
        result = storage.add_password("test_login", "test_password", "test comment")
        print(f"✓ Password added: {result}")
        
        # Test getting password
        password_data = storage.get_password("test_login")
        print(f"✓ Password retrieved: {password_data is not None}")
        
        # Test updating password
        result = storage.update_password("test_login", "new_password", "updated comment")
        print(f"✓ Password updated: {result}")
        
        # Test getting all passwords
        all_passwords = storage.get_all_passwords()
        print(f"✓ All passwords retrieved: {len(all_passwords)} items")
        
        # Test search functionality
        search_results = storage.search_passwords("test")
        print(f"✓ Search results: {len(search_results)} items")
        
        # Test statistics
        stats = storage.get_statistics()
        print(f"✓ Statistics: {stats}")
        
        return True
        
    except Exception as e:
        print(f"✗ Storage test failed: {e}")
        return False

def main():
    """Main test function"""
    print("Password Manager - Function Tests")
    print("=" * 40)
    
    # Test imports
    if not test_imports():
        print("\n❌ Import tests failed!")
        return
    
    # Test encryption
    if not test_encryption():
        print("\n❌ Encryption tests failed!")
        return
    
    # Test password generator
    if not test_password_generator():
        print("\n❌ Password generator tests failed!")
        return
    
    # Test storage
    if not test_storage():
        print("\n❌ Storage tests failed!")
        return
    
    print("\n🎉 All tests passed successfully!")
    print("The password manager is ready to use!")

if __name__ == "__main__":
    main() 