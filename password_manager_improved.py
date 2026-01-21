#!/usr/bin/env python3
"""
Improved Password Manager - Main Application
"""

import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys
import threading
import time

# Import our modules
from constants import *
from logger import setup_logger, log_error, log_info, log_debug
from encryption import EncryptionManager
from storage import PasswordStorage
from password_generator import PasswordGenerator
from auto_lock import AutoLock
from ui_dialogs import PasswordManagerDialogs

try:
    import pyperclip
except ImportError:
    pyperclip = None
    print("Warning: pyperclip not available. Clipboard operations will be disabled.")

class ImprovedPasswordManager:
    """Improved Password Manager with modular architecture"""
    
    def __init__(self):
        """Initialize the password manager"""
        try:
            # Setup logger first
            self.logger = setup_logger()
            log_info(self.logger, "Starting Improved Password Manager")
            
            # Initialize core components
            self.encryption_manager = EncryptionManager(self.logger)
            self.storage = PasswordStorage(self.encryption_manager, self.logger)
            self.password_generator = PasswordGenerator(self.logger)
            
            # Initialize UI
            self.root = tk.Tk()
            self.root.title(TITLE)
            self.root.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
            self.root.resizable(True, True)
            
            # Setup auto-lock
            self.auto_lock = AutoLock(self.logger, self._handle_auto_lock)
            
            # Setup dialogs
            self.dialogs = PasswordManagerDialogs(self.root, self.logger)
            
            # Initialize UI variables
            self._setup_ui_variables()
            
            # Setup UI
            self._setup_ui()
            
            # Setup event bindings
            self._setup_event_bindings()
            
            # Check master password
            self._check_master_password()
            
            # Update status
            self._update_status()
            
            # Setup window close handler
            self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
            
            log_info(self.logger, "Password Manager initialized successfully")
            
        except Exception as e:
            log_error(self.logger, e, "initialization")
            messagebox.showerror("Error", f"Failed to initialize password manager: {e}")
            if hasattr(self, 'root'):
                self.root.destroy()
            raise
    
    def _setup_ui_variables(self):
        """Setup UI variables"""
        try:
            # Input variables
            self.login_var = tk.StringVar()
            self.password_var = tk.StringVar()
            self.comment_var = tk.StringVar()
            self.search_var = tk.StringVar()
            
            # Password generator variables
            self.gen_length_var = tk.IntVar(value=DEFAULT_PASSWORD_LENGTH)
            self.gen_uppercase_var = tk.BooleanVar(value=True)
            self.gen_digits_var = tk.BooleanVar(value=True)
            self.gen_symbols_var = tk.BooleanVar(value=True)
            self.gen_mnemonic_var = tk.BooleanVar(value=False)
            
            # UI state variables
            self.show_password_var = tk.BooleanVar()
            self.editing_login = None
            self.settings = {
                'clear_clipboard': True,
                'confirm_deletion': True,
                'clear_clipboard_seconds': 15
            }
            
        except Exception as e:
            log_error(self.logger, e, "setup_ui_variables")
            raise
    
    def _setup_ui(self):
        """Setup the main user interface"""
        try:
            # Create main frame
            main_frame = ttk.Frame(self.root, padding="10")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            # Configure grid weights
            self.root.columnconfigure(0, weight=1)
            self.root.rowconfigure(0, weight=1)
            main_frame.columnconfigure(1, weight=1)
            
            # Title
            title_label = ttk.Label(main_frame, text=TITLE, font=("Arial", 16, "bold"))
            title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
            
            # Create UI sections
            self._create_input_section(main_frame)
            self._create_generator_section(main_frame)
            self._create_buttons_section(main_frame)
            self._create_search_section(main_frame)
            self._create_list_section(main_frame)
            self._create_status_bar(main_frame)
            self._create_menu_bar()
            
        except Exception as e:
            log_error(self.logger, e, "setup_ui")
            raise
    
    def _create_menu_bar(self):
        """Create menu bar"""
        try:
            menubar = tk.Menu(self.root)
            self.root.config(menu=menubar)
            
            # File menu
            file_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="File", menu=file_menu)
            file_menu.add_command(label="Export", command=self._show_export_dialog)
            file_menu.add_command(label="Import", command=self._show_import_dialog)
            file_menu.add_separator()
            file_menu.add_command(label="Settings", command=self._show_settings_dialog)
            file_menu.add_separator()
            file_menu.add_command(label="Exit", command=self._on_closing)
            
            # Tools menu
            tools_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Tools", menu=tools_menu)
            tools_menu.add_command(label="Password Generator", command=self._show_generator_dialog)
            tools_menu.add_command(label="Password Strength Checker", command=self._show_strength_checker)
            
            # Help menu
            help_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Help", menu=help_menu)
            help_menu.add_command(label="About", command=self._show_about_dialog)
            
        except Exception as e:
            log_error(self.logger, e, "create_menu_bar")
    
    def _create_input_section(self, parent):
        """Create input fields section"""
        try:
            input_frame = ttk.LabelFrame(parent, text="Add/Edit Password", padding="10")
            input_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
            input_frame.columnconfigure(1, weight=1)
            
            # Login field
            ttk.Label(input_frame, text="Login:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
            login_entry = ttk.Entry(input_frame, textvariable=self.login_var, width=40)
            login_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
            
            # Password field
            ttk.Label(input_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
            password_entry = ttk.Entry(input_frame, textvariable=self.password_var, width=40, show="*")
            password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
            
            # Show/hide password button
            show_password_cb = ttk.Checkbutton(input_frame, text="Show", variable=self.show_password_var,
                                              command=lambda: self._toggle_password_visibility(password_entry))
            show_password_cb.grid(row=1, column=2, padx=(0, 10))
            
            # Comment field
            ttk.Label(input_frame, text="Comment:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10))
            comment_entry = ttk.Entry(input_frame, textvariable=self.comment_var, width=40)
            comment_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
            
        except Exception as e:
            log_error(self.logger, e, "create_input_section")
    
    def _create_generator_section(self, parent):
        """Create password generator section"""
        try:
            generator_frame = ttk.LabelFrame(parent, text="Password Generator", padding="10")
            generator_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
            generator_frame.columnconfigure(1, weight=1)
            
            # Length
            ttk.Label(generator_frame, text="Length:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
            length_spinbox = ttk.Spinbox(generator_frame, from_=MIN_PASSWORD_LENGTH, to=MAX_PASSWORD_LENGTH, 
                                        textvariable=self.gen_length_var, width=10)
            length_spinbox.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
            
            # Options
            ttk.Checkbutton(generator_frame, text="Uppercase", variable=self.gen_uppercase_var).grid(row=0, column=2, padx=(0, 10))
            ttk.Checkbutton(generator_frame, text="Digits", variable=self.gen_digits_var).grid(row=0, column=3, padx=(0, 10))
            ttk.Checkbutton(generator_frame, text="Symbols", variable=self.gen_symbols_var).grid(row=0, column=4, padx=(0, 10))
            ttk.Checkbutton(generator_frame, text="Mnemonic", variable=self.gen_mnemonic_var).grid(row=0, column=5, padx=(0, 10))
            
            # Generate and Use buttons
            ttk.Button(generator_frame, text="Generate", command=self._generate_password).grid(row=1, column=0, columnspan=2, pady=(10, 0))
            ttk.Button(generator_frame, text="Use Password", command=self._use_generated_password).grid(row=1, column=2, columnspan=3, pady=(10, 0))
            
        except Exception as e:
            log_error(self.logger, e, "create_generator_section")
    
    def _create_buttons_section(self, parent):
        """Create action buttons section"""
        try:
            buttons_frame = ttk.Frame(parent)
            buttons_frame.grid(row=3, column=0, columnspan=3, pady=(0, 10))
            
            ttk.Button(buttons_frame, text="Save", command=self._save_password).pack(side=tk.LEFT, padx=(0, 10))
            ttk.Button(buttons_frame, text="Clear", command=self._clear_fields).pack(side=tk.LEFT, padx=(0, 10))
            ttk.Button(buttons_frame, text="Edit Selected", command=self._edit_selected).pack(side=tk.LEFT, padx=(0, 10))
            ttk.Button(buttons_frame, text="Delete Selected", command=self._delete_selected).pack(side=tk.LEFT, padx=(0, 10))
            
        except Exception as e:
            log_error(self.logger, e, "create_buttons_section")
    
    def _create_search_section(self, parent):
        """Create search section"""
        try:
            search_frame = ttk.Frame(parent)
            search_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
            search_frame.columnconfigure(1, weight=1)
            
            ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 10))
            search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
            search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
            search_entry.bind('<KeyRelease>', self._search_passwords)
            
            ttk.Button(search_frame, text="Clear Search", command=self._clear_search).pack(side=tk.LEFT)
            
        except Exception as e:
            log_error(self.logger, e, "create_search_section")
    
    def _create_list_section(self, parent):
        """Create passwords list section"""
        try:
            list_frame = ttk.LabelFrame(parent, text="Saved Passwords", padding="10")
            list_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
            list_frame.columnconfigure(0, weight=1)
            list_frame.rowconfigure(0, weight=1)
            parent.rowconfigure(5, weight=1)
            
            # Create Treeview with additional columns
            columns = ('Login', 'Password', 'Comment', 'Created', 'Modified')
            self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
            
            # Define headings
            for col in columns:
                self.tree.heading(col, text=col, command=lambda c=col: self._sort_treeview(c))
                self.tree.column(col, width=150, minwidth=100)
            
            # Scrollbars
            v_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
            h_scrollbar = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
            self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
            
            # Grid layout
            self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
            h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
            
            # Bind events
            self.tree.bind('<Double-1>', self._on_item_double_click)
            self.tree.bind('<Button-3>', self._show_context_menu)
            
            # Create context menu
            self._create_context_menu()
            
        except Exception as e:
            log_error(self.logger, e, "create_list_section")
    
    def _create_context_menu(self):
        """Create right-click context menu"""
        try:
            self.context_menu = tk.Menu(self.root, tearoff=0)
            self.context_menu.add_command(label="Copy Login", command=lambda: self._copy_field('login'))
            self.context_menu.add_command(label="Copy Password", command=lambda: self._copy_field('password'))
            self.context_menu.add_command(label="Copy Comment", command=lambda: self._copy_field('comment'))
            self.context_menu.add_separator()
            self.context_menu.add_command(label="Show/Hide Password", command=self._toggle_password_display)
            self.context_menu.add_separator()
            self.context_menu.add_command(label="Edit", command=self._edit_selected)
            self.context_menu.add_command(label="Delete", command=self._delete_selected)
            
        except Exception as e:
            log_error(self.logger, e, "create_context_menu")
    
    def _create_status_bar(self, parent):
        """Create status bar"""
        try:
            status_frame = ttk.Frame(parent)
            status_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))
            status_frame.columnconfigure(0, weight=1)
            
            # Status label
            self.status_var = tk.StringVar(value="Ready")
            status_label = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
            status_label.grid(row=0, column=0, sticky=(tk.W, tk.E))
            
            # Password count label
            self.count_var = tk.StringVar(value="0 passwords")
            count_label = ttk.Label(status_frame, textvariable=self.count_var, relief=tk.SUNKEN, anchor=tk.E)
            count_label.grid(row=0, column=1, sticky=(tk.E, tk.W))
            
            # Auto-lock timer label
            self.lock_timer_var = tk.StringVar(value="")
            lock_timer_label = ttk.Label(status_frame, textvariable=self.lock_timer_var, relief=tk.SUNKEN, anchor=tk.E)
            lock_timer_label.grid(row=0, column=2, sticky=(tk.E, tk.W), padx=(5, 0))
            
        except Exception as e:
            log_error(self.logger, e, "create_status_bar")
    
    def _setup_event_bindings(self):
        """Setup keyboard shortcuts and event bindings"""
        try:
            # Hotkeys
            self.root.bind(HOTKEY_GENERATE, lambda e: self._generate_password())
            self.root.bind(HOTKEY_SAVE, lambda e: self._save_password())
            self.root.bind(HOTKEY_CLEAR, lambda e: self._clear_fields())
            self.root.bind(HOTKEY_SEARCH, lambda e: self._focus_search())
            self.root.bind(HOTKEY_EXIT, lambda e: self._on_closing())
            
            # Activity tracking
            self.root.bind('<Key>', lambda e: self._update_activity())
            self.root.bind('<Button-1>', lambda e: self._update_activity())
            self.root.bind('<Motion>', lambda e: self._update_activity())
            
        except Exception as e:
            log_error(self.logger, e, "setup_event_bindings")
    
    def _check_master_password(self):
        """Check if master password is set, if not create one"""
        try:
            if os.path.exists(ENCRYPTION_FILE):
                # Prompt for master password to decrypt existing data
                self._verify_master_password()
            else:
                # Create new master password
                self._create_master_password()
            
            # Ensure we have an encryption key before proceeding
            if not self.encryption_manager.encryption_key:
                # If no key was set, create a default empty state
                self.storage.passwords_data = []
                
        except Exception as e:
            log_error(self.logger, e, "check_master_password")
            messagebox.showerror("Error", f"Failed to initialize password manager: {e}")
            self.storage.passwords_data = []
    
    def _verify_master_password(self):
        """Verify master password to decrypt existing data"""
        try:
            dialog = self.dialogs.create_master_password_dialog("Enter Master Password", is_new=False)
            if not dialog:
                return
            
            # Wait for dialog result
            self.root.wait_window(dialog)
            
            if dialog.result:
                try:
                    if not self.encryption_manager.load_salt():
                        result = messagebox.askyesno(
                            "Data Unavailable",
                            "Salt file is missing or invalid. Existing data cannot be decrypted.\n"
                            "Start a new vault? This will overwrite the current encrypted file."
                        )
                        if result:
                            self._create_master_password()
                        return

                    # Try to derive key and decrypt data
                    self.encryption_manager.derive_key(dialog.result)
                    self.storage.load_from_file()
                    # Refresh the UI after successful decryption
                    self._refresh_password_list()
                    self._update_status()
                    log_info(self.logger, "Master password verified successfully")
                except Exception as e:
                    log_error(self.logger, e, "master_password_verification")
                    messagebox.showerror("Error", f"Incorrect master password or corrupted data: {e}")
                    self._verify_master_password()  # Retry
            else:
                # User cancelled, try again
                self._verify_master_password()
                
        except Exception as e:
            log_error(self.logger, e, "verify_master_password")
            messagebox.showerror("Error", f"Failed to verify master password: {e}")
    
    def _create_master_password(self):
        """Create a new master password"""
        try:
            dialog = self.dialogs.create_master_password_dialog("Create Master Password", is_new=True)
            if not dialog:
                return
            
            # Wait for dialog result
            self.root.wait_window(dialog)
            
            if dialog.result:
                try:
                    # Create master password hash and encryption key
                    self.encryption_manager.generate_salt()
                    self.encryption_manager.hash_password(dialog.result)
                    self.encryption_manager.derive_key(dialog.result)
                    self.storage.save_to_file()  # Save empty data with new master password
                    # Refresh the UI after creating master password
                    self._refresh_password_list()
                    self._update_status()
                    log_info(self.logger, "Master password created successfully")
                except Exception as e:
                    log_error(self.logger, e, "master_password_creation")
                    messagebox.showerror("Error", f"Failed to create master password: {e}")
                    self._create_master_password()  # Retry
            else:
                # User cancelled, try again
                self._create_master_password()
                
        except Exception as e:
            log_error(self.logger, e, "create_master_password")
            messagebox.showerror("Error", f"Failed to create master password: {e}")
    
    def _handle_auto_lock(self):
        """Handle auto-lock event"""
        try:
            # Clear sensitive data
            self.encryption_manager.clear_sensitive_data()
            self.storage.passwords_data = []
            
            # Refresh UI
            self._refresh_password_list()
            self._update_status()
            
            # Show lock message
            messagebox.showinfo("Auto-Lock", "Application locked due to inactivity. Please enter master password to unlock.")
            
            # Prompt for master password
            self._verify_master_password()
            
        except Exception as e:
            log_error(self.logger, e, "handle_auto_lock")
    
    def _update_activity(self):
        """Update activity timestamp for auto-lock"""
        try:
            self.auto_lock.update_activity()
        except Exception as e:
            log_error(self.logger, e, "update_activity")
    
    def _generate_password(self):
        """Generate a password using the password generator"""
        try:
            password = self.password_generator.generate_password(
                length=self.gen_length_var.get(),
                use_uppercase=self.gen_uppercase_var.get(),
                use_digits=self.gen_digits_var.get(),
                use_symbols=self.gen_symbols_var.get(),
                use_mnemonic=self.gen_mnemonic_var.get()
            )
            
            self.password_var.set(password)
            log_info(self.logger, "Password generated successfully")
            
        except Exception as e:
            log_error(self.logger, e, "generate_password")
            messagebox.showerror("Error", f"Failed to generate password: {e}")
    
    def _use_generated_password(self):
        """Use the generated password in the password field"""
        try:
            self._generate_password()
        except Exception as e:
            log_error(self.logger, e, "use_generated_password")
    
    def _save_password(self):
        """Save current password entry"""
        try:
            login = self.login_var.get().strip()
            password = self.password_var.get()
            comment = self.comment_var.get().strip()
            
            if not login or not password:
                messagebox.showwarning("Warning", "Login and password are required!")
                return
            
            # Check if login already exists
            existing_entry = self.storage.get_password(login)
            
            if self.editing_login and self.editing_login != login:
                if existing_entry:
                    messagebox.showerror("Error", "Login already exists!")
                    return

                if not self.storage.delete_password(self.editing_login):
                    messagebox.showerror("Error", "Failed to rename existing entry!")
                    return

                if self.storage.add_password(login, password, comment):
                    messagebox.showinfo("Success", "Password updated successfully!")
                else:
                    messagebox.showerror("Error", "Failed to save password!")
                    return
            elif existing_entry:
                # Update existing entry
                if self.storage.update_password(login, password, comment):
                    messagebox.showinfo("Success", "Password updated successfully!")
                else:
                    messagebox.showerror("Error", "Failed to update password!")
                    return
            else:
                # Add new entry
                if self.storage.add_password(login, password, comment):
                    messagebox.showinfo("Success", "Password saved successfully!")
                else:
                    messagebox.showerror("Error", "Failed to save password!")
                    return
            
            # Save to file and refresh UI
            self.storage.save_to_file()
            self._refresh_password_list()
            self._clear_fields()
            self._update_status()
            
        except Exception as e:
            log_error(self.logger, e, "save_password")
            messagebox.showerror("Error", f"Failed to save password: {e}")
    
    def _clear_fields(self):
        """Clear input fields"""
        try:
            self.login_var.set('')
            self.password_var.set('')
            self.comment_var.set('')
            self.editing_login = None
        except Exception as e:
            log_error(self.logger, e, "clear_fields")
    
    def _search_passwords(self, event=None):
        """Search passwords by login or comment"""
        try:
            search_term = self.search_var.get()
            results = self.storage.search_passwords(search_term)
            self._display_passwords(results)
        except Exception as e:
            log_error(self.logger, e, "search_passwords")
    
    def _clear_search(self):
        """Clear search and show all passwords"""
        try:
            self.search_var.set('')
            self._refresh_password_list()
        except Exception as e:
            log_error(self.logger, e, "clear_search")
    
    def _refresh_password_list(self):
        """Refresh the password list display"""
        try:
            all_passwords = self.storage.get_all_passwords()
            self._display_passwords(all_passwords)
        except Exception as e:
            log_error(self.logger, e, "refresh_password_list")
    
    def _display_passwords(self, passwords):
        """Display passwords in the treeview"""
        try:
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Add items
            for password_data in passwords:
                created = password_data.get('created', '')
                modified = password_data.get('modified', '')
                
                # Format dates
                if created:
                    try:
                        created = created[:10]  # Show only date part
                    except:
                        created = ''
                
                if modified:
                    try:
                        modified = modified[:10]  # Show only date part
                    except:
                        modified = ''
                
                self.tree.insert('', tk.END, values=(
                    password_data.get('login', ''),
                    '*' * len(password_data.get('password', '')),
                    password_data.get('comment', ''),
                    created,
                    modified
                ), tags=('password_row',))
                
        except Exception as e:
            log_error(self.logger, e, "display_passwords")
    
    def _get_selected_item(self):
        """Get the currently selected item"""
        try:
            selection = self.tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select an item first!")
                return None
            
            item = self.tree.item(selection[0])
            login = item['values'][0]
            
            # Find corresponding data
            password_data = self.storage.get_password(login)
            if not password_data:
                messagebox.showerror("Error", "Selected item not found in data!")
                return None
            
            return password_data
            
        except Exception as e:
            log_error(self.logger, e, "get_selected_item")
            return None
    
    def _edit_selected(self):
        """Edit the selected password entry"""
        try:
            password_data = self._get_selected_item()
            if not password_data:
                return
            
            # Fill fields with selected data
            self.login_var.set(password_data.get('login', ''))
            self.password_var.set(password_data.get('password', ''))
            self.comment_var.set(password_data.get('comment', ''))
            self.editing_login = password_data.get('login')
            
        except Exception as e:
            log_error(self.logger, e, "edit_selected")
            messagebox.showerror("Error", f"Failed to edit selected item: {e}")
    
    def _delete_selected(self):
        """Delete the selected password entry"""
        try:
            password_data = self._get_selected_item()
            if not password_data:
                return
            
            # Confirm deletion
            if self.settings.get('confirm_deletion', True):
                result = messagebox.askyesno(
                    "Confirm Delete",
                    f"Are you sure you want to delete the password for '{password_data.get('login')}'?"
                )
                if not result:
                    return
            
            # Delete from storage
            if self.storage.delete_password(password_data.get('login')):
                self.storage.save_to_file()
                self._refresh_password_list()
                self._update_status()
                messagebox.showinfo("Success", "Password deleted successfully!")
            else:
                messagebox.showerror("Error", "Failed to delete password!")
                
        except Exception as e:
            log_error(self.logger, e, "delete_selected")
            messagebox.showerror("Error", f"Failed to delete selected item: {e}")
    
    def _on_item_double_click(self, event):
        """Handle double-click on list item"""
        try:
            self._edit_selected()
        except Exception as e:
            log_error(self.logger, e, "on_item_double_click")
    
    def _show_context_menu(self, event):
        """Show context menu on right-click"""
        try:
            # Select the item under cursor
            item = self.tree.identify_row(event.y)
            if item:
                self.tree.selection_set(item)
                self.context_menu.post(event.x_root, event.y_root)
        except Exception as e:
            log_error(self.logger, e, "show_context_menu")
    
    def _copy_field(self, field_type):
        """Copy specific field to clipboard"""
        try:
            if pyperclip is None:
                messagebox.showwarning("Warning", "Clipboard operations are not available. Please install pyperclip.")
                return
            
            password_data = self._get_selected_item()
            if not password_data:
                return
            
            value = password_data.get(field_type, '')
            if value:
                try:
                    pyperclip.copy(value)
                    messagebox.showinfo("Success", f"{field_type.capitalize()} copied to clipboard!")
                    if self.settings.get('clear_clipboard', True):
                        self._schedule_clipboard_clear(value)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to copy to clipboard: {e}")
                    
        except Exception as e:
            log_error(self.logger, e, "copy_field")

    def _schedule_clipboard_clear(self, value):
        """Clear clipboard after a delay if content hasn't changed"""
        try:
            delay_seconds = self.settings.get('clear_clipboard_seconds', 15)
            delay_ms = max(1000, int(delay_seconds * 1000))

            def clear_if_unchanged():
                try:
                    if pyperclip and pyperclip.paste() == value:
                        pyperclip.copy('')
                except Exception as e:
                    log_error(self.logger, e, "clipboard_clear")

            self.root.after(delay_ms, clear_if_unchanged)
        except Exception as e:
            log_error(self.logger, e, "schedule_clipboard_clear")
    
    def _toggle_password_display(self):
        """Toggle password visibility in the list for selected item"""
        try:
            password_data = self._get_selected_item()
            if not password_data:
                return
            
            selection = self.tree.selection()
            if not selection:
                return
            
            item = selection[0]
            current_values = self.tree.item(item)['values']
            
            # Toggle between masked and actual password
            if current_values[1] == '*' * len(password_data.get('password', '')):
                # Show actual password
                new_values = (
                    current_values[0],
                    password_data.get('password', ''),
                    current_values[2],
                    current_values[3],
                    current_values[4]
                )
            else:
                # Hide password
                new_values = (
                    current_values[0],
                    '*' * len(password_data.get('password', '')),
                    current_values[2],
                    current_values[3],
                    current_values[4]
                )
            
            self.tree.item(item, values=new_values)
            
        except Exception as e:
            log_error(self.logger, e, "toggle_password_display")
    
    def _toggle_password_visibility(self, entry):
        """Toggle password field visibility"""
        try:
            if self.show_password_var.get():
                entry.config(show="")
            else:
                entry.config(show="*")
        except Exception as e:
            log_error(self.logger, e, "toggle_password_visibility")
    
    def _sort_treeview(self, col):
        """Sort treeview by column"""
        try:
            # Get all items
            items = [(self.tree.set(item, col), item) for item in self.tree.get_children('')]
            
            # Sort items
            items.sort()
            
            # Rearrange items in sorted positions
            for index, (val, item) in enumerate(items):
                self.tree.move(item, '', index)
                
        except Exception as e:
            log_error(self.logger, e, "sort_treeview")
    
    def _update_status(self):
        """Update status bar with current information"""
        try:
            if hasattr(self, 'status_var') and hasattr(self, 'count_var'):
                stats = self.storage.get_statistics()
                count = stats.get('total_passwords', 0)
                self.count_var.set(f"{count} password{'s' if count != 1 else ''}")
                self.status_var.set("Ready")
                
                # Update auto-lock timer
                lock_info = self.auto_lock.get_lock_status_info()
                if lock_info['is_locked']:
                    self.lock_timer_var.set("LOCKED")
                else:
                    self.lock_timer_var.set(f"LOCK IN {lock_info['time_until_lock_formatted']}")
                    
        except Exception as e:
            log_error(self.logger, e, "update_status")
    
    def _focus_search(self):
        """Focus on search field"""
        try:
            # Find search entry and focus it
            for widget in self.root.winfo_children():
                if isinstance(widget, tk.Toplevel):
                    continue
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Entry) and child.cget('textvariable') == str(self.search_var):
                        child.focus_set()
                        child.select_range(0, tk.END)
                        return
        except Exception as e:
            log_error(self.logger, e, "focus_search")
    
    def _show_export_dialog(self):
        """Show export dialog"""
        try:
            dialog = self.dialogs.create_export_dialog()
            if dialog:
                self.root.wait_window(dialog)
                if dialog.result:
                    # Handle export
                    self._handle_export(dialog.result)
        except Exception as e:
            log_error(self.logger, e, "show_export_dialog")
    
    def _show_import_dialog(self):
        """Show import dialog"""
        try:
            dialog = self.dialogs.create_import_dialog()
            if dialog:
                self.root.wait_window(dialog)
                if dialog.result:
                    # Handle import
                    self._handle_import(dialog.result)
        except Exception as e:
            log_error(self.logger, e, "show_import_dialog")
    
    def _show_settings_dialog(self):
        """Show settings dialog"""
        try:
            dialog = self.dialogs.create_settings_dialog()
            if dialog:
                self.root.wait_window(dialog)
                if dialog.result:
                    # Handle settings
                    self._handle_settings(dialog.result)
        except Exception as e:
            log_error(self.logger, e, "show_settings_dialog")
    
    def _show_generator_dialog(self):
        """Show password generator dialog"""
        try:
            # For now, just focus on the generator section
            self._focus_search()
        except Exception as e:
            log_error(self.logger, e, "show_generator_dialog")
    
    def _show_strength_checker(self):
        """Show password strength checker"""
        try:
            # Get current password
            password = self.password_var.get()
            if not password:
                messagebox.showwarning("Warning", "Please enter a password to check!")
                return
            
            # Calculate strength
            score = self.password_generator.calculate_password_strength(password)
            description, color = self.password_generator.get_strength_description(score)
            
            # Show result
            messagebox.showinfo("Password Strength", 
                              f"Password: {password}\n"
                              f"Strength: {description}\n"
                              f"Score: {score}/100")
            
        except Exception as e:
            log_error(self.logger, e, "show_strength_checker")
    
    def _show_about_dialog(self):
        """Show about dialog"""
        try:
            messagebox.showinfo("About Password Manager", 
                              f"{TITLE}\n\n"
                              f"Version: 3.0.0\n"
                              f"Features:\n"
                              f"- PBKDF2 key derivation\n"
                              f"- AES-256 encryption\n"
                              f"- Auto-lock protection\n"
                              f"- Password strength checker\n"
                              f"- Import/Export support\n\n"
                              f"Built with Python and Tkinter")
        except Exception as e:
            log_error(self.logger, e, "show_about_dialog")
    
    def _handle_export(self, export_data):
        """Handle password export"""
        try:
            export_format = export_data.get('format')
            file_path = export_data.get('file_path')
            include_passwords = export_data.get('include_passwords', False)

            if export_format == "json":
                if include_passwords:
                    success = self.storage.export_to_json_with_passwords(file_path)
                else:
                    success = self.storage.export_to_json(file_path)
            elif export_format == "csv":
                success = self.storage.export_to_csv(file_path, include_passwords=include_passwords)
            else:
                messagebox.showerror("Export", "Unsupported export format.")
                return

            if success:
                messagebox.showinfo("Export", f"Exported passwords to {file_path}")
            else:
                messagebox.showerror("Export", "Failed to export passwords.")
        except Exception as e:
            log_error(self.logger, e, "handle_export")
    
    def _handle_import(self, import_data):
        """Handle password import"""
        try:
            import_format = import_data.get('format')
            file_path = import_data.get('file_path')
            duplicate_handling = import_data.get('duplicate_handling', 'skip')

            if import_format == "json":
                imported_count = self.storage.import_from_json_with_duplicates(file_path, duplicate_handling)
            elif import_format == "csv":
                imported_count = self.storage.import_from_csv(file_path, duplicate_handling)
            else:
                messagebox.showerror("Import", "Unsupported import format.")
                return

            if imported_count > 0:
                self.storage.save_to_file()
                self._refresh_password_list()
                self._update_status()
                messagebox.showinfo("Import", f"Imported {imported_count} passwords.")
            else:
                messagebox.showwarning("Import", "No passwords were imported. Check the file format.")
        except Exception as e:
            log_error(self.logger, e, "handle_import")
    
    def _handle_settings(self, settings_data):
        """Handle settings changes"""
        try:
            # Update auto-lock timeout
            if 'timeout_minutes' in settings_data:
                timeout_seconds = settings_data['timeout_minutes'] * 60
                self.auto_lock.set_timeout(timeout_seconds)

            if 'clear_clipboard' in settings_data:
                self.settings['clear_clipboard'] = bool(settings_data['clear_clipboard'])

            if 'confirm_deletion' in settings_data:
                self.settings['confirm_deletion'] = bool(settings_data['confirm_deletion'])
            
            log_info(self.logger, f"Settings updated: {settings_data}")
            messagebox.showinfo("Settings", "Settings updated successfully!")
            
        except Exception as e:
            log_error(self.logger, e, "handle_settings")
    
    def _on_closing(self):
        """Handle application closing"""
        try:
            # Check for unsaved changes
            if self.storage.has_unsaved_changes:
                result = messagebox.askyesnocancel(
                    "Unsaved Changes",
                    "You have unsaved changes. Save before closing?"
                )
                
                if result is True:  # Save and close
                    self.storage.save_to_file()
                elif result is None:  # Cancel
                    return
            
            # Clear sensitive data
            self.encryption_manager.clear_sensitive_data()
            
            # Stop auto-lock monitoring
            self.auto_lock.stop_monitoring()
            
            # Close application
            log_info(self.logger, "Password Manager shutting down")
            self.root.destroy()
            
        except Exception as e:
            log_error(self.logger, e, "on_closing")
            self.root.destroy()
    
    def run(self):
        """Start the application"""
        try:
            if hasattr(self, 'root') and self.root:
                # Start status update timer
                self._start_status_timer()
                
                # Start main loop
                self.root.mainloop()
                
        except Exception as e:
            log_error(self.logger, e, "run")
            messagebox.showerror("Error", f"Application failed to run: {e}")
    
    def _start_status_timer(self):
        """Start timer for status updates"""
        try:
            def update_status_timer():
                try:
                    self._update_status()
                    # Schedule next update
                    self.root.after(1000, update_status_timer)  # Update every second
                except Exception as e:
                    log_error(self.logger, e, "status_timer")
            
            # Start the timer
            update_status_timer()
            
        except Exception as e:
            log_error(self.logger, e, "start_status_timer")

def main():
    """Main function"""
    try:
        app = ImprovedPasswordManager()
        app.run()
    except Exception as e:
        print(f"Failed to start password manager: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main() 
