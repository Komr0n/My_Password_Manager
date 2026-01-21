"""
Logging module for Password Manager
"""

import logging
import os
from constants import LOG_FILE, LOG_LEVEL, LOG_FORMAT

def setup_logger():
    """Setup and configure logger"""
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Configure logger
    logger = logging.getLogger('PasswordManager')
    logger.setLevel(getattr(logging, LOG_LEVEL.upper()))
    
    # Create formatter
    formatter = logging.Formatter(LOG_FORMAT)
    
    # Create file handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def log_security_event(logger, event_type, details=""):
    """Log security-related events"""
    logger.warning(f"SECURITY: {event_type} - {details}")

def log_error(logger, error, context=""):
    """Log errors with context"""
    logger.error(f"ERROR: {error} - Context: {context}")

def log_info(logger, message):
    """Log informational messages"""
    logger.info(f"INFO: {message}")

def log_debug(logger, message):
    """Log debug messages"""
    logger.debug(f"DEBUG: {message}") 