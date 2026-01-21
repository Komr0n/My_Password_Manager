"""
Password Generator module for Password Manager
"""

import secrets
import string
from constants import (
    LOWERCASE_CHARS, UPPERCASE_CHARS, DIGIT_CHARS, SYMBOL_CHARS,
    MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH, DEFAULT_PASSWORD_LENGTH
)
from logger import log_info, log_error

class PasswordGenerator:
    """Generates secure passwords based on user preferences"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def generate_password(self, length=DEFAULT_PASSWORD_LENGTH, use_uppercase=True, 
                         use_digits=True, use_symbols=True, use_mnemonic=False):
        """Generate a secure password"""
        try:
            # Validate length
            if not MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
                raise ValueError(f"Password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}")
            
            if use_mnemonic:
                return self._generate_mnemonic_password(length)
            else:
                return self._generate_random_password(length, use_uppercase, use_digits, use_symbols)
                
        except Exception as e:
            log_error(self.logger, e, "generate_password")
            raise
    
    def _generate_random_password(self, length, use_uppercase, use_digits, use_symbols):
        """Generate a random password with specified characteristics"""
        try:
            # Build character set
            chars = LOWERCASE_CHARS  # Always include lowercase
            
            if use_uppercase:
                chars += UPPERCASE_CHARS
            if use_digits:
                chars += DIGIT_CHARS
            if use_symbols:
                chars += SYMBOL_CHARS
            
            if not chars:
                raise ValueError("At least one character type must be selected")
            
            # Generate initial password
            password = ''.join(secrets.choice(chars) for _ in range(length))
            
            # Ensure password meets requirements
            password = self._ensure_password_requirements(
                password, use_uppercase, use_digits, use_symbols
            )
            
            log_info(self.logger, f"Generated random password: length={length}, "
                    f"uppercase={use_uppercase}, digits={use_digits}, symbols={use_symbols}")
            
            return password
            
        except Exception as e:
            log_error(self.logger, e, "random_password_generation")
            raise
    
    def _generate_mnemonic_password(self, length):
        """Generate a mnemonic password using word patterns"""
        try:
            # Simple mnemonic pattern: word + numbers + symbols
            words = [
                "secure", "strong", "safe", "protect", "guard", "shield",
                "defend", "secure", "private", "secret", "hidden", "safe"
            ]
            
            # Select random word
            word = secrets.choice(words)
            
            # Add numbers and symbols
            numbers = ''.join(secrets.choice(DIGIT_CHARS) for _ in range(2))
            symbols = ''.join(secrets.choice(SYMBOL_CHARS) for _ in range(2))
            
            # Combine and shuffle
            password = word + numbers + symbols
            
            # Ensure minimum length
            while len(password) < length:
                password += secrets.choice(LOWERCASE_CHARS + DIGIT_CHARS)
            
            # Truncate if too long
            if len(password) > length:
                password = password[:length]
            
            log_info(self.logger, f"Generated mnemonic password: length={len(password)}")
            return password
            
        except Exception as e:
            log_error(self.logger, e, "mnemonic_password_generation")
            raise
    
    def _ensure_password_requirements(self, password, use_uppercase, use_digits, use_symbols):
        """Ensure password meets all specified requirements"""
        try:
            # Check and fix uppercase requirement
            if use_uppercase and not any(c.isupper() for c in password):
                # Replace a random character with uppercase
                pos = secrets.randbelow(len(password))
                password = password[:pos] + secrets.choice(UPPERCASE_CHARS) + password[pos+1:]
            
            # Check and fix digit requirement
            if use_digits and not any(c.isdigit() for c in password):
                # Replace a random character with digit
                pos = secrets.randbelow(len(password))
                password = password[:pos] + secrets.choice(DIGIT_CHARS) + password[pos+1:]
            
            # Check and fix symbol requirement
            if use_symbols and not any(c in SYMBOL_CHARS for c in password):
                # Replace a random character with symbol
                pos = secrets.randbelow(len(password))
                password = password[:pos] + secrets.choice(SYMBOL_CHARS) + password[pos+1:]
            
            return password
            
        except Exception as e:
            log_error(self.logger, e, "password_requirements_check")
            return password
    
    def calculate_password_strength(self, password):
        """Calculate password strength score (0-100)"""
        try:
            score = 0
            
            # Length bonus
            if len(password) >= 12:
                score += 25
            elif len(password) >= 8:
                score += 15
            else:
                score += 5
            
            # Character variety bonus
            if any(c.islower() for c in password):
                score += 10
            if any(c.isupper() for c in password):
                score += 10
            if any(c.isdigit() for c in password):
                score += 10
            if any(c in SYMBOL_CHARS for c in password):
                score += 15
            
            # Complexity bonus
            unique_chars = len(set(password))
            if unique_chars >= len(password) * 0.8:
                score += 20
            elif unique_chars >= len(password) * 0.6:
                score += 10
            
            # Penalty for common patterns
            if password.lower() in ['password', '123456', 'qwerty', 'admin']:
                score -= 30
            
            # Ensure score is within bounds
            score = max(0, min(100, score))
            
            return score
            
        except Exception as e:
            log_error(self.logger, e, "password_strength_calculation")
            return 0
    
    def get_strength_description(self, score):
        """Get human-readable strength description"""
        try:
            if score >= 80:
                return "Very Strong", "green"
            elif score >= 60:
                return "Strong", "darkgreen"
            elif score >= 40:
                return "Moderate", "orange"
            elif score >= 20:
                return "Weak", "red"
            else:
                return "Very Weak", "darkred"
        except Exception as e:
            log_error(self.logger, e, "strength_description")
            return "Unknown", "black"
    
    def generate_pronounceable_password(self, length=DEFAULT_PASSWORD_LENGTH):
        """Generate a pronounceable password"""
        try:
            # Vowel and consonant patterns
            vowels = 'aeiou'
            consonants = 'bcdfghjklmnpqrstvwxyz'
            
            password = ""
            for i in range(length):
                if i % 2 == 0:  # Even positions get consonants
                    password += secrets.choice(consonants)
                else:  # Odd positions get vowels
                    password += secrets.choice(vowels)
            
            # Ensure minimum length
            while len(password) < length:
                password += secrets.choice(vowels + consonants)
            
            # Truncate if too long
            if len(password) > length:
                password = password[:length]
            
            log_info(self.logger, f"Generated pronounceable password: length={len(password)}")
            return password
            
        except Exception as e:
            log_error(self.logger, e, "pronounceable_password_generation")
            raise
    
    def validate_password_requirements(self, password, min_length=MIN_PASSWORD_LENGTH):
        """Validate if password meets minimum requirements"""
        try:
            if len(password) < min_length:
                return False, f"Password must be at least {min_length} characters long"
            
            if not any(c.islower() for c in password):
                return False, "Password must contain at least one lowercase letter"
            
            if not any(c.isupper() for c in password):
                return False, "Password must contain at least one uppercase letter"
            
            if not any(c.isdigit() for c in password):
                return False, "Password must contain at least one digit"
            
            if not any(c in SYMBOL_CHARS for c in password):
                return False, "Password must contain at least one special character"
            
            return True, "Password meets all requirements"
            
        except Exception as e:
            log_error(self.logger, e, "password_validation")
            return False, "Error validating password" 