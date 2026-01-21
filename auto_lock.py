"""
Auto-lock module for Password Manager
"""

import time
import threading
from constants import AUTO_LOCK_TIMEOUT, ACTIVITY_CHECK_INTERVAL
from logger import log_info, log_security_event, log_error

class AutoLock:
    """Manages automatic locking of the application"""
    
    def __init__(self, logger, lock_callback):
        self.logger = logger
        self.lock_callback = lock_callback
        self.last_activity = time.time()
        self.is_locked = False
        self.is_running = False
        self.monitor_thread = None
        
        # Start monitoring
        self.start_monitoring()
    
    def start_monitoring(self):
        """Start the auto-lock monitoring thread"""
        try:
            if not self.is_running:
                self.is_running = True
                self.monitor_thread = threading.Thread(
                    target=self._monitor_activity,
                    daemon=True,
                    name="AutoLockMonitor"
                )
                self.monitor_thread.start()
                log_info(self.logger, "Auto-lock monitoring started")
        except Exception as e:
            log_error(self.logger, e, "start_monitoring")
    
    def stop_monitoring(self):
        """Stop the auto-lock monitoring thread"""
        try:
            self.is_running = False
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=1.0)
            log_info(self.logger, "Auto-lock monitoring stopped")
        except Exception as e:
            log_error(self.logger, e, "stop_monitoring")
    
    def _monitor_activity(self):
        """Monitor activity and trigger auto-lock when needed"""
        try:
            while self.is_running:
                if not self.is_locked:
                    current_time = time.time()
                    time_since_activity = current_time - self.last_activity
                    
                    if time_since_activity >= AUTO_LOCK_TIMEOUT:
                        log_security_event(self.logger, "auto_lock_triggered", 
                                        f"inactive_time={time_since_activity:.1f}s")
                        self._trigger_lock()
                
                # Sleep for the check interval
                time.sleep(ACTIVITY_CHECK_INTERVAL)
                
        except Exception as e:
            log_error(self.logger, e, "activity_monitoring")
    
    def _trigger_lock(self):
        """Trigger the lock mechanism"""
        try:
            self.is_locked = True
            log_security_event(self.logger, "application_locked", "auto-lock timeout")
            
            # Call the lock callback
            if self.lock_callback:
                self.lock_callback()
                
        except Exception as e:
            log_error(self.logger, e, "trigger_lock")
    
    def update_activity(self):
        """Update the last activity timestamp"""
        try:
            self.last_activity = time.time()
            log_info(self.logger, "Activity timestamp updated")
        except Exception as e:
            log_error(self.logger, e, "update_activity")
    
    def unlock(self):
        """Unlock the application"""
        try:
            self.is_locked = False
            self.update_activity()
            log_security_event(self.logger, "application_unlocked", "user authentication")
        except Exception as e:
            log_error(self.logger, e, "unlock")
    
    def is_application_locked(self):
        """Check if the application is currently locked"""
        return self.is_locked
    
    def get_time_until_lock(self):
        """Get time remaining until auto-lock (in seconds)"""
        try:
            if self.is_locked:
                return 0
            
            time_since_activity = time.time() - self.last_activity
            time_remaining = max(0, AUTO_LOCK_TIMEOUT - time_since_activity)
            return time_remaining
        except Exception as e:
            log_error(self.logger, e, "get_time_until_lock")
            return 0
    
    def get_lock_status_info(self):
        """Get comprehensive lock status information"""
        try:
            time_until_lock = self.get_time_until_lock()
            minutes = int(time_until_lock // 60)
            seconds = int(time_until_lock % 60)
            
            return {
                'is_locked': self.is_locked,
                'time_until_lock': time_until_lock,
                'time_until_lock_formatted': f"{minutes:02d}:{seconds:02d}",
                'last_activity': self.last_activity,
                'timeout_seconds': AUTO_LOCK_TIMEOUT
            }
        except Exception as e:
            log_error(self.logger, e, "get_lock_status_info")
            return {
                'is_locked': True,
                'time_until_lock': 0,
                'time_until_lock_formatted': "00:00",
                'last_activity': 0,
                'timeout_seconds': AUTO_LOCK_TIMEOUT
            }
    
    def reset_timer(self):
        """Reset the auto-lock timer"""
        try:
            self.update_activity()
            log_info(self.logger, "Auto-lock timer reset")
        except Exception as e:
            log_error(self.logger, e, "reset_timer")
    
    def set_timeout(self, timeout_seconds):
        """Set a custom auto-lock timeout"""
        try:
            global AUTO_LOCK_TIMEOUT
            AUTO_LOCK_TIMEOUT = max(60, timeout_seconds)  # Minimum 1 minute
            log_info(self.logger, f"Auto-lock timeout set to {AUTO_LOCK_TIMEOUT} seconds")
        except Exception as e:
            log_error(self.logger, e, "set_timeout")
    
    def get_timeout(self):
        """Get current auto-lock timeout"""
        return AUTO_LOCK_TIMEOUT 