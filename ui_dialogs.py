"""
UI Dialogs module for Password Manager
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from constants import MIN_PASSWORD_LENGTH, MAX_LOGIN_LENGTH, MAX_COMMENT_LENGTH
from logger import log_info, log_error

class PasswordManagerDialogs:
    """Collection of dialog windows for the password manager"""
    
    def __init__(self, parent, logger):
        self.parent = parent
        self.logger = logger
    
    def create_master_password_dialog(self, title, is_new=True):
        """Create master password input dialog"""
        try:
            dialog = tk.Toplevel(self.parent)
            dialog.title(title)
            dialog.geometry("400x200")
            dialog.transient(self.parent)
            dialog.grab_set()
            
            # Center the dialog
            self._center_dialog(dialog)
            
            frame = ttk.Frame(dialog, padding="20")
            frame.pack(fill=tk.BOTH, expand=True)
            
            ttk.Label(frame, text=title, font=("Arial", 12, "bold")).pack(pady=(0, 20))
            
            password_var = tk.StringVar()
            confirm_var = tk.StringVar()
            
            # Password field
            ttk.Label(frame, text="Enter master password:").pack(anchor=tk.W)
            password_entry = ttk.Entry(frame, textvariable=password_var, show="*")
            password_entry.pack(fill=tk.X, pady=(5, 10))
            
            # Confirm field (only for new passwords)
            if is_new:
                ttk.Label(frame, text="Confirm master password:").pack(anchor=tk.W)
                confirm_entry = ttk.Entry(frame, textvariable=confirm_var, show="*")
                confirm_entry.pack(fill=tk.X, pady=(5, 20))
            else:
                confirm_entry = None
            
            # Buttons
            button_frame = ttk.Frame(frame)
            button_frame.pack(fill=tk.X, pady=(0, 10))
            
            if is_new:
                ttk.Button(button_frame, text="Set Password", 
                          command=lambda: self._validate_and_close(dialog, password_var, confirm_var, True)).pack(side=tk.RIGHT)
            else:
                ttk.Button(button_frame, text="Unlock", 
                          command=lambda: self._validate_and_close(dialog, password_var, None, False)).pack(side=tk.RIGHT)
            
            ttk.Button(button_frame, text="Cancel", 
                      command=dialog.destroy).pack(side=tk.RIGHT, padx=(0, 10))
            
            # Focus and bind events
            password_entry.focus()
            password_entry.bind('<Return>', lambda e: confirm_entry.focus() if confirm_entry else self._validate_and_close(dialog, password_var, None, False))
            if confirm_entry:
                confirm_entry.bind('<Return>', lambda e: self._validate_and_close(dialog, password_var, confirm_var, True))
            
            # Store variables for access
            dialog.password_var = password_var
            dialog.confirm_var = confirm_var
            dialog.result = None
            
            return dialog
            
        except Exception as e:
            log_error(self.logger, e, "create_master_password_dialog")
            return None
    
    def _validate_and_close(self, dialog, password_var, confirm_var, is_new):
        """Validate password and close dialog"""
        try:
            password = password_var.get()
            
            if is_new:
                confirm = confirm_var.get()
                
                if password != confirm:
                    messagebox.showerror("Error", "Passwords do not match!")
                    return
                
                if len(password) < MIN_PASSWORD_LENGTH:
                    messagebox.showerror("Error", f"Password must be at least {MIN_PASSWORD_LENGTH} characters long!")
                    return
            
            dialog.result = password
            dialog.destroy()
            
        except Exception as e:
            log_error(self.logger, e, "validate_and_close")
            messagebox.showerror("Error", f"Validation failed: {e}")
    
    def create_export_dialog(self):
        """Create export options dialog"""
        try:
            dialog = tk.Toplevel(self.parent)
            dialog.title("Export Passwords")
            dialog.geometry("500x300")
            dialog.transient(self.parent)
            dialog.grab_set()
            
            self._center_dialog(dialog)
            
            frame = ttk.Frame(dialog, padding="20")
            frame.pack(fill=tk.BOTH, expand=True)
            
            ttk.Label(frame, text="Export Passwords", font=("Arial", 12, "bold")).pack(pady=(0, 20))
            
            # Export options
            options_frame = ttk.LabelFrame(frame, text="Export Options", padding="10")
            options_frame.pack(fill=tk.X, pady=(0, 20))
            
            export_format = tk.StringVar(value="json")
            ttk.Radiobutton(options_frame, text="JSON (recommended)", 
                           variable=export_format, value="json").pack(anchor=tk.W)
            ttk.Radiobutton(options_frame, text="CSV", 
                           variable=export_format, value="csv").pack(anchor=tk.W)
            
            # Include options
            include_passwords = tk.BooleanVar(value=False)
            ttk.Checkbutton(options_frame, text="Include passwords (less secure)", 
                           variable=include_passwords).pack(anchor=tk.W, pady=(10, 0))
            
            # File selection
            file_frame = ttk.LabelFrame(frame, text="Export File", padding="10")
            file_frame.pack(fill=tk.X, pady=(0, 20))
            
            file_var = tk.StringVar()
            ttk.Entry(file_frame, textvariable=file_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
            ttk.Button(file_frame, text="Browse", 
                      command=lambda: self._browse_export_file(dialog, file_var, export_format.get())).pack(side=tk.RIGHT)
            
            # Buttons
            button_frame = ttk.Frame(frame)
            button_frame.pack(fill=tk.X)
            
            ttk.Button(button_frame, text="Export", 
                      command=lambda: self._export_passwords(dialog, file_var.get(), export_format.get(), include_passwords.get())).pack(side=tk.RIGHT)
            ttk.Button(button_frame, text="Cancel", 
                      command=dialog.destroy).pack(side=tk.RIGHT, padx=(0, 10))
            
            # Store variables
            dialog.export_format = export_format
            dialog.include_passwords = include_passwords
            dialog.file_var = file_var
            dialog.result = None
            
            return dialog
            
        except Exception as e:
            log_error(self.logger, e, "create_export_dialog")
            return None
    
    def create_import_dialog(self):
        """Create import options dialog"""
        try:
            dialog = tk.Toplevel(self.parent)
            dialog.title("Import Passwords")
            dialog.geometry("500x250")
            dialog.transient(self.parent)
            dialog.grab_set()
            
            self._center_dialog(dialog)
            
            frame = ttk.Frame(dialog, padding="20")
            frame.pack(fill=tk.BOTH, expand=True)
            
            ttk.Label(frame, text="Import Passwords", font=("Arial", 12, "bold")).pack(pady=(0, 20))
            
            # Import options
            options_frame = ttk.LabelFrame(frame, text="Import Options", padding="10")
            options_frame.pack(fill=tk.X, pady=(0, 20))
            
            import_format = tk.StringVar(value="json")
            ttk.Radiobutton(options_frame, text="JSON", 
                           variable=import_format, value="json").pack(anchor=tk.W)
            ttk.Radiobutton(options_frame, text="CSV", 
                           variable=import_format, value="csv").pack(anchor=tk.W)
            
            # Duplicate handling
            duplicate_handling = tk.StringVar(value="skip")
            ttk.Label(options_frame, text="Duplicate handling:").pack(anchor=tk.W, pady=(10, 0))
            ttk.Radiobutton(options_frame, text="Skip duplicates", 
                           variable=duplicate_handling, value="skip").pack(anchor=tk.W)
            ttk.Radiobutton(options_frame, text="Overwrite duplicates", 
                           variable=duplicate_handling, value="overwrite").pack(anchor=tk.W)
            
            # File selection
            file_frame = ttk.LabelFrame(frame, text="Import File", padding="10")
            file_frame.pack(fill=tk.X, pady=(0, 20))
            
            file_var = tk.StringVar()
            ttk.Entry(file_frame, textvariable=file_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
            ttk.Button(file_frame, text="Browse", 
                      command=lambda: self._browse_import_file(dialog, file_var, import_format.get())).pack(side=tk.RIGHT)
            
            # Buttons
            button_frame = ttk.Frame(frame)
            button_frame.pack(fill=tk.X)
            
            ttk.Button(button_frame, text="Import", 
                      command=lambda: self._import_passwords(dialog, file_var.get(), import_format.get(), duplicate_handling.get())).pack(side=tk.RIGHT)
            ttk.Button(button_frame, text="Cancel", 
                      command=dialog.destroy).pack(side=tk.RIGHT, padx=(0, 10))
            
            # Store variables
            dialog.import_format = import_format
            dialog.duplicate_handling = duplicate_handling
            dialog.file_var = file_var
            dialog.result = None
            
            return dialog
            
        except Exception as e:
            log_error(self.logger, e, "create_import_dialog")
            return None
    
    def create_settings_dialog(self):
        """Create settings dialog"""
        try:
            dialog = tk.Toplevel(self.parent)
            dialog.title("Settings")
            dialog.geometry("400x300")
            dialog.transient(self.parent)
            dialog.grab_set()
            
            self._center_dialog(dialog)
            
            frame = ttk.Frame(dialog, padding="20")
            frame.pack(fill=tk.BOTH, expand=True)
            
            ttk.Label(frame, text="Settings", font=("Arial", 12, "bold")).pack(pady=(0, 20))
            
            # Auto-lock settings
            lock_frame = ttk.LabelFrame(frame, text="Auto-Lock Settings", padding="10")
            lock_frame.pack(fill=tk.X, pady=(0, 20))
            
            ttk.Label(lock_frame, text="Auto-lock timeout (minutes):").pack(anchor=tk.W)
            timeout_var = tk.IntVar(value=5)
            timeout_spinbox = ttk.Spinbox(lock_frame, from_=1, to=60, textvariable=timeout_var, width=10)
            timeout_spinbox.pack(anchor=tk.W, pady=(5, 0))
            
            # Security settings
            security_frame = ttk.LabelFrame(frame, text="Security Settings", padding="10")
            security_frame.pack(fill=tk.X, pady=(0, 20))
            
            clear_clipboard = tk.BooleanVar(value=True)
            ttk.Checkbutton(security_frame, text="Clear clipboard after copying", 
                           variable=clear_clipboard).pack(anchor=tk.W)
            
            confirm_deletion = tk.BooleanVar(value=True)
            ttk.Checkbutton(security_frame, text="Confirm password deletion", 
                           variable=confirm_deletion).pack(anchor=tk.W, pady=(5, 0))
            
            # Buttons
            button_frame = ttk.Frame(frame)
            button_frame.pack(fill=tk.X)
            
            ttk.Button(button_frame, text="Save", 
                      command=lambda: self._save_settings(dialog, timeout_var.get(), clear_clipboard.get(), confirm_deletion.get())).pack(side=tk.RIGHT)
            ttk.Button(button_frame, text="Cancel", 
                      command=dialog.destroy).pack(side=tk.RIGHT, padx=(0, 10))
            
            # Store variables
            dialog.timeout_var = timeout_var
            dialog.clear_clipboard = clear_clipboard
            dialog.confirm_deletion = confirm_deletion
            dialog.result = None
            
            return dialog
            
        except Exception as e:
            log_error(self.logger, e, "create_settings_dialog")
            return None
    
    def _center_dialog(self, dialog):
        """Center dialog on parent window"""
        try:
            dialog.update_idletasks()
            x = self.parent.winfo_rootx() + (self.parent.winfo_width() // 2) - (dialog.winfo_width() // 2)
            y = self.parent.winfo_rooty() + (self.parent.winfo_height() // 2) - (dialog.winfo_height() // 2)
            dialog.geometry(f"+{x}+{y}")
        except Exception as e:
            log_error(self.logger, e, "center_dialog")
    
    def _browse_export_file(self, dialog, file_var, format_type):
        """Browse for export file"""
        try:
            if format_type == "json":
                filename = filedialog.asksaveasfilename(
                    defaultextension=".json",
                    filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
                )
            else:  # CSV
                filename = filedialog.asksaveasfilename(
                    defaultextension=".csv",
                    filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
                )
            
            if filename:
                file_var.set(filename)
                
        except Exception as e:
            log_error(self.logger, e, "browse_export_file")
    
    def _browse_import_file(self, dialog, file_var, format_type):
        """Browse for import file"""
        try:
            if format_type == "json":
                filename = filedialog.askopenfilename(
                    filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
                )
            else:  # CSV
                filename = filedialog.askopenfilename(
                    filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
                )
            
            if filename:
                file_var.set(filename)
                
        except Exception as e:
            log_error(self.logger, e, "browse_import_file")
    
    def _export_passwords(self, dialog, file_path, format_type, include_passwords):
        """Handle password export"""
        try:
            if not file_path:
                messagebox.showwarning("Warning", "Please select a file path!")
                return
            
            # Store result and close dialog
            dialog.result = {
                'action': 'export',
                'file_path': file_path,
                'format': format_type,
                'include_passwords': include_passwords
            }
            dialog.destroy()
            
        except Exception as e:
            log_error(self.logger, e, "export_passwords")
            messagebox.showerror("Error", f"Export failed: {e}")
    
    def _import_passwords(self, dialog, file_path, format_type, duplicate_handling):
        """Handle password import"""
        try:
            if not file_path:
                messagebox.showwarning("Warning", "Please select a file to import!")
                return
            
            # Store result and close dialog
            dialog.result = {
                'action': 'import',
                'file_path': file_path,
                'format': format_type,
                'duplicate_handling': duplicate_handling
            }
            dialog.destroy()
            
        except Exception as e:
            log_error(self.logger, e, "import_passwords")
            messagebox.showerror("Error", f"Import failed: {e}")
    
    def _save_settings(self, dialog, timeout_minutes, clear_clipboard, confirm_deletion):
        """Save settings"""
        try:
            # Store result and close dialog
            dialog.result = {
                'action': 'save_settings',
                'timeout_minutes': timeout_minutes,
                'clear_clipboard': clear_clipboard,
                'confirm_deletion': confirm_deletion
            }
            dialog.destroy()
            
        except Exception as e:
            log_error(self.logger, e, "save_settings")
            messagebox.showerror("Error", f"Failed to save settings: {e}")
    
    def show_confirm_dialog(self, title, message, confirm_text="Yes", cancel_text="No"):
        """Show confirmation dialog"""
        try:
            result = messagebox.askyesno(title, message)
            return result
        except Exception as e:
            log_error(self.logger, e, "show_confirm_dialog")
            return False
    
    def show_info_dialog(self, title, message):
        """Show information dialog"""
        try:
            messagebox.showinfo(title, message)
        except Exception as e:
            log_error(self.logger, e, "show_info_dialog")
    
    def show_error_dialog(self, title, message):
        """Show error dialog"""
        try:
            messagebox.showerror(title, message)
        except Exception as e:
            log_error(self.logger, e, "show_error_dialog")
    
    def show_warning_dialog(self, title, message):
        """Show warning dialog"""
        try:
            messagebox.showwarning(title, message)
        except Exception as e:
            log_error(self.logger, e, "show_warning_dialog") 