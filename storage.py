"""
Storage module for Password Manager
"""

import os
import json
import csv
from datetime import datetime
from constants import ENCRYPTION_FILE, BACKUP_FILE, MAX_LOGIN_LENGTH, MAX_COMMENT_LENGTH
from logger import log_info, log_error, log_security_event

class PasswordStorage:
    """Manages password data storage and retrieval"""
    
    def __init__(self, encryption_manager, logger):
        self.encryption_manager = encryption_manager
        self.logger = logger
        self.passwords_data = []
        self.has_unsaved_changes = False
    
    def add_password(self, login, password, comment=""):
        """Add a new password entry"""
        try:
            # Validate input
            if not self._validate_input(login, password, comment):
                return False
            
            # Check for duplicate login
            if self._login_exists(login):
                log_error(self.logger, f"Login already exists: {login}", "add_password")
                return False
            
            # Create password entry with metadata
            password_entry = {
                'login': login.strip(),
                'password': password,
                'comment': comment.strip(),
                'created': datetime.now().isoformat(),
                'modified': datetime.now().isoformat()
            }
            
            self.passwords_data.append(password_entry)
            self.has_unsaved_changes = True
            
            log_info(self.logger, f"Added password for login: {login}")
            return True
            
        except Exception as e:
            log_error(self.logger, e, "add_password")
            return False
    
    def update_password(self, login, password, comment=""):
        """Update an existing password entry"""
        try:
            # Validate input
            if not self._validate_input(login, password, comment):
                return False
            
            # Find existing entry
            for entry in self.passwords_data:
                if entry['login'] == login:
                    # Update fields
                    entry['password'] = password
                    entry['comment'] = comment.strip()
                    entry['modified'] = datetime.now().isoformat()
                    
                    self.has_unsaved_changes = True
                    log_info(self.logger, f"Updated password for login: {login}")
                    return True
            
            log_error(self.logger, f"Login not found: {login}", "update_password")
            return False
            
        except Exception as e:
            log_error(self.logger, e, "update_password")
            return False
    
    def delete_password(self, login):
        """Delete a password entry"""
        try:
            for i, entry in enumerate(self.passwords_data):
                if entry['login'] == login:
                    del self.passwords_data[i]
                    self.has_unsaved_changes = True
                    log_info(self.logger, f"Deleted password for login: {login}")
                    return True
            
            log_error(self.logger, f"Login not found: {login}", "delete_password")
            return False
            
        except Exception as e:
            log_error(self.logger, e, "delete_password")
            return False
    
    def get_password(self, login):
        """Get password entry by login"""
        try:
            for entry in self.passwords_data:
                if entry['login'] == login:
                    return entry.copy()  # Return a copy to prevent modification
            return None
        except Exception as e:
            log_error(self.logger, e, "get_password")
            return None
    
    def get_all_passwords(self):
        """Get all password entries"""
        return [entry.copy() for entry in self.passwords_data]
    
    def search_passwords(self, search_term):
        """Search passwords by login or comment"""
        try:
            if not search_term:
                return self.get_all_passwords()
            
            search_term = search_term.lower()
            results = []
            
            for entry in self.passwords_data:
                login = entry['login'].lower()
                comment = entry['comment'].lower()
                
                if search_term in login or search_term in comment:
                    results.append(entry.copy())
            
            log_info(self.logger, f"Search for '{search_term}' returned {len(results)} results")
            return results
            
        except Exception as e:
            log_error(self.logger, e, "search_passwords")
            return []
    
    def save_to_file(self, file_path=ENCRYPTION_FILE):
        """Save passwords to encrypted file"""
        try:
            if not self.encryption_manager.encryption_key:
                log_error(self.logger, "Encryption key not set", "save_to_file")
                return False

            if not self.encryption_manager.salt:
                self.encryption_manager.generate_salt()
            
            # Create backup before saving
            backup_path = self.encryption_manager.backup_file(file_path)
            
            # Encrypt data
            encrypted_data = self.encryption_manager.encrypt_data(self.passwords_data)
            
            # Write to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(encrypted_data)

            # Save salt for future key derivation
            self.encryption_manager.save_salt()
            
            self.has_unsaved_changes = False
            log_info(self.logger, f"Saved {len(self.passwords_data)} passwords to {file_path}")
            
            if backup_path:
                log_info(self.logger, f"Backup created: {backup_path}")
            
            return True
            
        except Exception as e:
            log_error(self.logger, e, "save_to_file")
            return False
    
    def load_from_file(self, file_path=ENCRYPTION_FILE):
        """Load passwords from encrypted file"""
        try:
            if not os.path.exists(file_path):
                self.passwords_data = []
                log_info(self.logger, f"File not found, starting with empty data: {file_path}")
                return True
            
            # Read encrypted data
            with open(file_path, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()
            
            if not encrypted_data.strip():
                self.passwords_data = []
                log_info(self.logger, "Empty file, starting with empty data")
                return True
            
            # Decrypt data
            self.passwords_data = self.encryption_manager.decrypt_data(encrypted_data)
            
            # Validate data structure
            if not isinstance(self.passwords_data, list):
                raise ValueError("Invalid data format: expected list")
            
            log_info(self.logger, f"Loaded {len(self.passwords_data)} passwords from {file_path}")
            return True
            
        except Exception as e:
            log_error(self.logger, e, "load_from_file")
            self.passwords_data = []
            return False
    
    def export_to_json(self, file_path):
        """Export passwords to JSON file (unencrypted)"""
        return self._export_to_json(file_path, include_passwords=False)

    def export_to_json_with_passwords(self, file_path):
        """Export passwords to JSON file (includes passwords)"""
        return self._export_to_json(file_path, include_passwords=True)

    def _export_to_json(self, file_path, include_passwords=False):
        """Export passwords to JSON file (unencrypted)"""
        try:
            # Create export data without sensitive fields
            export_data = []
            for entry in self.passwords_data:
                export_entry = {
                    'login': entry['login'],
                    'comment': entry['comment'],
                    'created': entry['created'],
                    'modified': entry['modified']
                }
                if include_passwords:
                    export_entry['password'] = entry['password']
                export_data.append(export_entry)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            log_info(self.logger, f"Exported {len(export_data)} entries to {file_path}")
            return True
            
        except Exception as e:
            log_error(self.logger, e, "export_to_json")
            return False

    def export_to_csv(self, file_path, include_passwords=False):
        """Export passwords to CSV file (unencrypted)"""
        try:
            fieldnames = ['login', 'password', 'comment', 'created', 'modified']

            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for entry in self.passwords_data:
                    row = {
                        'login': entry['login'],
                        'password': entry['password'] if include_passwords else '',
                        'comment': entry['comment'],
                        'created': entry['created'],
                        'modified': entry['modified']
                    }
                    writer.writerow(row)

            log_info(self.logger, f"Exported {len(self.passwords_data)} entries to CSV {file_path}")
            return True
        except Exception as e:
            log_error(self.logger, e, "export_to_csv")
            return False
    
    def import_from_json(self, file_path):
        """Import passwords from JSON file"""
        return self.import_from_json_with_duplicates(file_path, duplicate_handling="skip")

    def import_from_json_with_duplicates(self, file_path, duplicate_handling="skip"):
        """Import passwords from JSON file with duplicate handling"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            if not isinstance(import_data, list):
                raise ValueError("Invalid JSON format: expected list")
            
            imported_count = 0
            for entry in import_data:
                login = entry.get('login', '').strip()
                password = entry.get('password', '')
                comment = entry.get('comment', '')

                if not login or not password:
                    continue

                if self._login_exists(login):
                    if duplicate_handling == "overwrite":
                        if self.update_password(login, password, comment):
                            imported_count += 1
                    else:
                        continue
                else:
                    if self.add_password(login, password, comment):
                        imported_count += 1
            
            log_info(self.logger, f"Imported {imported_count} passwords from {file_path}")
            return imported_count
            
        except Exception as e:
            log_error(self.logger, e, "import_from_json")
            return 0

    def import_from_csv(self, file_path, duplicate_handling="skip"):
        """Import passwords from CSV file with duplicate handling"""
        try:
            imported_count = 0
            with open(file_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    login = (row.get('login') or '').strip()
                    password = row.get('password') or ''
                    comment = row.get('comment') or ''

                    if not login or not password:
                        continue

                    if self._login_exists(login):
                        if duplicate_handling == "overwrite":
                            if self.update_password(login, password, comment):
                                imported_count += 1
                        else:
                            continue
                    else:
                        if self.add_password(login, password, comment):
                            imported_count += 1

            log_info(self.logger, f"Imported {imported_count} passwords from CSV {file_path}")
            return imported_count
        except Exception as e:
            log_error(self.logger, e, "import_from_csv")
            return 0
    
    def _validate_input(self, login, password, comment):
        """Validate input data"""
        try:
            if not login or not login.strip():
                log_error(self.logger, "Login is required", "input_validation")
                return False
            
            if not password:
                log_error(self.logger, "Password is required", "input_validation")
                return False
            
            if len(login.strip()) > MAX_LOGIN_LENGTH:
                log_error(self.logger, f"Login too long: {len(login)} > {MAX_LOGIN_LENGTH}", "input_validation")
                return False
            
            if len(comment) > MAX_COMMENT_LENGTH:
                log_error(self.logger, f"Comment too long: {len(comment)} > {MAX_COMMENT_LENGTH}", "input_validation")
                return False
            
            return True
            
        except Exception as e:
            log_error(self.logger, e, "input_validation")
            return False
    
    def _login_exists(self, login):
        """Check if login already exists"""
        return any(entry['login'] == login for entry in self.passwords_data)
    
    def get_statistics(self):
        """Get password statistics"""
        try:
            total = len(self.passwords_data)
            with_comments = sum(1 for entry in self.passwords_data if entry['comment'])
            
            # Count by creation month
            creation_months = {}
            for entry in self.passwords_data:
                if 'created' in entry:
                    try:
                        month = datetime.fromisoformat(entry['created']).strftime('%Y-%m')
                        creation_months[month] = creation_months.get(month, 0) + 1
                    except:
                        pass
            
            return {
                'total_passwords': total,
                'with_comments': with_comments,
                'creation_months': creation_months,
                'has_unsaved_changes': self.has_unsaved_changes
            }
            
        except Exception as e:
            log_error(self.logger, e, "get_statistics")
            return {}
    
    def clear_all_data(self):
        """Clear all password data"""
        try:
            self.passwords_data.clear()
            self.has_unsaved_changes = True
            log_security_event(self.logger, "all_data_cleared", "user request")
            return True
        except Exception as e:
            log_error(self.logger, e, "clear_all_data")
            return False 
