"""
Constants for Password Manager
"""

# File paths
ENCRYPTION_FILE = "passwords.enc"
BACKUP_FILE = "passwords.enc.bak"
SALT_FILE = "passwords.enc.salt"

# Security settings
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 50
MAX_LOGIN_LENGTH = 100
MAX_COMMENT_LENGTH = 500
PBKDF2_ITERATIONS = 100000
SALT_LENGTH = 32
KEY_LENGTH = 32
IV_LENGTH = 16

# UI settings
WINDOW_WIDTH = 800
WINDOW_HEIGHT = 600
TITLE = "Password Manager"
DEFAULT_PASSWORD_LENGTH = 12

# Auto-lock settings
AUTO_LOCK_TIMEOUT = 300  # 5 minutes in seconds
ACTIVITY_CHECK_INTERVAL = 10  # seconds

# Character sets for password generation
LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGIT_CHARS = "0123456789"
SYMBOL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

# Logging
LOG_FILE = "password_manager.log"
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

# Hotkeys
HOTKEY_GENERATE = "<Control-g>"
HOTKEY_SAVE = "<Control-s>"
HOTKEY_CLEAR = "<Control-l>"
HOTKEY_SEARCH = "<Control-f>"
HOTKEY_EXIT = "<Control-q>" 
