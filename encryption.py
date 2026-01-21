"""
Encryption module for Password Manager
"""

import json
import base64
import hashlib
import hmac
import secrets
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from constants import PBKDF2_ITERATIONS, SALT_LENGTH, KEY_LENGTH, IV_LENGTH, SALT_FILE
from logger import log_security_event, log_error, log_debug, log_info

class EncryptionManager:
    """Manages encryption and decryption operations"""
    
    def __init__(self, logger):
        self.logger = logger
        self.encryption_key = None
        self.salt = None
    
    def generate_salt(self):
        """Generate a random salt"""
        try:
            self.salt = secrets.token_bytes(SALT_LENGTH)
            log_debug(self.logger, f"Generated new salt: {len(self.salt)} bytes")
            return self.salt
        except Exception as e:
            log_error(self.logger, e, "salt generation")
            raise
    
    def derive_key(self, password, salt=None):
        """Derive encryption key using PBKDF2"""
        try:
            if salt is not None:
                self.salt = salt

            if not self.salt:
                raise ValueError("Salt not set. Load or generate salt before deriving key.")
            
            # Use PBKDF2 for key derivation
            key = self._pbkdf2_hmac_sha256(
                password.encode('utf-8'),
                self.salt,
                PBKDF2_ITERATIONS,
                KEY_LENGTH
            )
            
            self.encryption_key = key
            log_debug(self.logger, f"Derived key using PBKDF2 with {PBKDF2_ITERATIONS} iterations")
            return key
        except Exception as e:
            log_error(self.logger, e, "key derivation")
            raise ValueError(f"Key derivation failed: {e}")
    
    def _pbkdf2_hmac_sha256(self, password, salt, iterations, dk_len):
        """Custom PBKDF2 implementation using HMAC-SHA256"""
        try:
            # First iteration
            u = hmac.new(password, salt + b'\x00\x00\x00\x01', hashlib.sha256).digest()
            result = u
            
            # Additional iterations
            for i in range(1, iterations):
                u = hmac.new(password, u, hashlib.sha256).digest()
                result = bytes(a ^ b for a, b in zip(result, u))
            
            # Return the first dk_len bytes
            return result[:dk_len]
        except Exception as e:
            log_error(self.logger, e, "pbkdf2_hmac_sha256")
            raise
    
    def hash_password(self, password):
        """Create a secure hash of the password with salt"""
        try:
            if not self.salt:
                self.generate_salt()
            
            # Use PBKDF2 for password hashing
            hash_value = self._pbkdf2_hmac_sha256(
                password.encode('utf-8'),
                self.salt,
                PBKDF2_ITERATIONS,
                KEY_LENGTH
            )
            
            # Combine salt and hash for storage
            combined = self.salt + hash_value
            log_security_event(self.logger, "password_hash_created", f"iterations={PBKDF2_ITERATIONS}")
            return base64.b64encode(combined).decode('utf-8')
        except Exception as e:
            log_error(self.logger, e, "password hashing")
            raise ValueError(f"Password hashing failed: {e}")
    
    def verify_password_hash(self, password, stored_hash):
        """Verify password against stored hash"""
        try:
            # Decode stored hash
            combined = base64.b64decode(stored_hash.encode('utf-8'))
            
            # Extract salt and hash
            stored_salt = combined[:SALT_LENGTH]
            stored_hash_value = combined[SALT_LENGTH:]
            
            # Derive hash with stored salt
            derived_hash = self._pbkdf2_hmac_sha256(
                password.encode('utf-8'),
                stored_salt,
                PBKDF2_ITERATIONS,
                KEY_LENGTH
            )
            
            # Constant-time comparison
            if len(derived_hash) != len(stored_hash_value):
                return False
            
            result = 0
            for a, b in zip(derived_hash, stored_hash_value):
                result |= a ^ b
            
            is_valid = result == 0
            log_security_event(self.logger, "password_verification", f"result={'success' if is_valid else 'failure'}")
            return is_valid
        except Exception as e:
            log_error(self.logger, e, "password verification")
            return False
    
    def encrypt_data(self, data):
        """Encrypt data using AES-256-CBC with random IV"""
        try:
            if not self.encryption_key:
                raise ValueError("Encryption key not set")
            
            # Generate random IV
            iv = secrets.token_bytes(IV_LENGTH)
            
            # Create cipher
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            
            # Convert data to JSON and encode
            json_data = json.dumps(data, ensure_ascii=False)
            padded_data = pad(json_data.encode('utf-8'), AES.block_size)
            
            # Encrypt data
            encrypted_data = cipher.encrypt(padded_data)
            
            # Combine IV and encrypted data
            combined = iv + encrypted_data
            result = base64.b64encode(combined).decode('utf-8')
            
            log_debug(self.logger, f"Encrypted data: {len(data)} items")
            return result
        except Exception as e:
            log_error(self.logger, e, "data encryption")
            raise ValueError(f"Encryption failed: {e}")
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data using AES-256-CBC"""
        try:
            if not self.encryption_key:
                raise ValueError("Encryption key not set")
            
            # Decode from base64
            data = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Check minimum data length
            min_length = IV_LENGTH + AES.block_size
            if len(data) < min_length:
                raise ValueError(f"Encrypted data too short: {len(data)} < {min_length}")
            
            # Extract IV and encrypted data
            iv = data[:IV_LENGTH]
            encrypted_data = data[IV_LENGTH:]
            
            # Create cipher
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            
            # Decrypt data
            decrypted_data = cipher.decrypt(encrypted_data)
            unpadded_data = unpad(decrypted_data, AES.block_size)
            
            # Parse JSON
            result = json.loads(unpadded_data.decode('utf-8'))
            
            log_debug(self.logger, f"Decrypted data: {len(result)} items")
            return result
        except Exception as e:
            log_error(self.logger, e, "data decryption")
            raise ValueError(f"Decryption failed: {e}")
    
    def clear_sensitive_data(self):
        """Securely clear sensitive data from memory"""
        try:
            if self.encryption_key:
                # Overwrite key with zeros
                self.encryption_key = b'\x00' * len(self.encryption_key)
                self.encryption_key = None
            
            if self.salt:
                # Overwrite salt with zeros
                self.salt = b'\x00' * len(self.salt)
                self.salt = None
            
            log_security_event(self.logger, "sensitive_data_cleared", "memory wiped")
        except Exception as e:
            log_error(self.logger, e, "clearing sensitive data")

    def save_salt(self, file_path=SALT_FILE):
        """Save salt to a file for future key derivation"""
        try:
            if not self.salt:
                raise ValueError("Salt not set")

            salt_data = base64.b64encode(self.salt).decode('utf-8')
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(salt_data)

            log_info(self.logger, f"Salt saved to {file_path}")
            return True
        except Exception as e:
            log_error(self.logger, e, "save_salt")
            return False

    def load_salt(self, file_path=SALT_FILE):
        """Load salt from a file"""
        try:
            if not os.path.exists(file_path):
                log_error(self.logger, f"Salt file not found: {file_path}", "load_salt")
                return False

            with open(file_path, 'r', encoding='utf-8') as f:
                salt_data = f.read().strip()

            if not salt_data:
                raise ValueError("Salt file is empty")

            self.salt = base64.b64decode(salt_data.encode('utf-8'))
            log_info(self.logger, f"Salt loaded from {file_path}")
            return True
        except Exception as e:
            log_error(self.logger, e, "load_salt")
            return False
    
    def backup_file(self, file_path):
        """Create a backup of the encryption file"""
        try:
            if os.path.exists(file_path):
                backup_path = f"{file_path}.bak"
                with open(file_path, 'rb') as src, open(backup_path, 'wb') as dst:
                    dst.write(src.read())
                log_info(self.logger, f"Created backup: {backup_path}")
                return backup_path
        except Exception as e:
            log_error(self.logger, e, "file backup")
            return None 
