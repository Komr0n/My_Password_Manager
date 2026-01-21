import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import base64
import hashlib
import secrets
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
try:
    import pyperclip  # For clipboard operations
except ImportError:
    pyperclip = None
    print("Warning: pyperclip not available. Clipboard operations will be disabled.")

class PasswordManager:
    def __init__(self):
        try:
            self.root = tk.Tk()
            self.root.title("Password Manager")
            self.root.geometry("800x600")
            self.root.resizable(True, True)
            
            # Encryption settings
            self.encryption_file = "passwords.enc"
            self.master_password_hash = None
            self.encryption_key = None
            
            # Data storage
            self.passwords_data = []
            
            # UI variables
            self.login_var = tk.StringVar()
            self.password_var = tk.StringVar()
            self.comment_var = tk.StringVar()
            self.search_var = tk.StringVar()
            
            # Password generator variables
            self.gen_length_var = tk.IntVar(value=12)
            self.gen_uppercase_var = tk.BooleanVar(value=True)
            self.gen_digits_var = tk.BooleanVar(value=True)
            self.gen_symbols_var = tk.BooleanVar(value=True)
            
            self.setup_ui()
            self.check_master_password()
            # Update status after master password is handled
            self.update_status()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize password manager: {e}")
            if hasattr(self, 'root'):
                self.root.destroy()
    
    def setup_ui(self):
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
            title_label = ttk.Label(main_frame, text="Password Manager", font=("Arial", 16, "bold"))
            title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
            
            # Input fields section
            self.create_input_section(main_frame)
            
            # Password generator section
            self.create_generator_section(main_frame)
            
            # Buttons section
            self.create_buttons_section(main_frame)
            
            # Search section
            self.create_search_section(main_frame)
            
            # Passwords list section
            self.create_list_section(main_frame)
            
            # Status bar
            self.create_status_bar(main_frame)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to setup UI: {e}")
            self.root.destroy()
    
    def create_input_section(self, parent):
        """Create input fields for login, password, and comment"""
        # Input frame
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
        self.show_password_var = tk.BooleanVar()
        show_password_cb = ttk.Checkbutton(input_frame, text="Show", variable=self.show_password_var,
                                          command=lambda: self.toggle_password_visibility(password_entry))
        show_password_cb.grid(row=1, column=2, padx=(0, 10))
        
        # Comment field
        ttk.Label(input_frame, text="Comment:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10))
        comment_entry = ttk.Entry(input_frame, textvariable=self.comment_var, width=40)
        comment_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
    
    def create_generator_section(self, parent):
        """Create password generator section"""
        # Generator frame
        generator_frame = ttk.LabelFrame(parent, text="Password Generator", padding="10")
        generator_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        generator_frame.columnconfigure(1, weight=1)
        
        # Length
        ttk.Label(generator_frame, text="Length:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        length_spinbox = ttk.Spinbox(generator_frame, from_=8, to=50, textvariable=self.gen_length_var, width=10)
        length_spinbox.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        # Options
        ttk.Checkbutton(generator_frame, text="Uppercase", variable=self.gen_uppercase_var).grid(row=0, column=2, padx=(0, 10))
        ttk.Checkbutton(generator_frame, text="Digits", variable=self.gen_digits_var).grid(row=0, column=3, padx=(0, 10))
        ttk.Checkbutton(generator_frame, text="Symbols", variable=self.gen_symbols_var).grid(row=0, column=4, padx=(0, 10))
        
        # Generate and Use buttons
        ttk.Button(generator_frame, text="Generate", command=self.generate_password).grid(row=1, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(generator_frame, text="Use Password", command=self.use_generated_password).grid(row=1, column=2, columnspan=3, pady=(10, 0))
    
    def create_buttons_section(self, parent):
        """Create action buttons"""
        # Buttons frame
        buttons_frame = ttk.Frame(parent)
        buttons_frame.grid(row=3, column=0, columnspan=3, pady=(0, 10))
        
        ttk.Button(buttons_frame, text="Save", command=self.save_password).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="Clear", command=self.clear_fields).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="Edit Selected", command=self.edit_selected).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(buttons_frame, text="Delete Selected", command=self.delete_selected).pack(side=tk.LEFT, padx=(0, 10))
    
    def create_search_section(self, parent):
        """Create search functionality"""
        # Search frame
        search_frame = ttk.Frame(parent)
        search_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        search_frame.columnconfigure(1, weight=1)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 10))
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        search_entry.bind('<KeyRelease>', self.search_passwords)
        
        ttk.Button(search_frame, text="Clear Search", command=self.clear_search).pack(side=tk.LEFT)
    
    def create_list_section(self, parent):
        """Create the passwords list display"""
        # List frame
        list_frame = ttk.LabelFrame(parent, text="Saved Passwords", padding="10")
        list_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        parent.rowconfigure(5, weight=1)
        
        # Create Treeview
        columns = ('Login', 'Password', 'Comment')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # Define headings
        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(c))
            self.tree.column(col, width=200, minwidth=100)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Bind double-click event
        self.tree.bind('<Double-1>', self.on_item_double_click)
        
        # Right-click context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy Login", command=lambda: self.copy_field('login'))
        self.context_menu.add_command(label="Copy Password", command=lambda: self.copy_field('password'))
        self.context_menu.add_command(label="Copy Comment", command=lambda: self.copy_field('comment'))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Show/Hide Password", command=self.toggle_password_display)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Edit", command=self.edit_selected)
        self.context_menu.add_command(label="Delete", command=self.delete_selected)
        
        self.tree.bind('<Button-3>', self.show_context_menu)
    
    def create_status_bar(self, parent):
        """Create status bar at the bottom"""
        # Status bar frame
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
    
    def check_master_password(self):
        """Check if master password is set, if not create one"""
        try:
            if os.path.exists(self.encryption_file):
                # Prompt for master password to decrypt existing data
                self.verify_master_password()
            else:
                # Create new master password
                self.create_master_password()
            
            # Ensure we have an encryption key before proceeding
            if not self.encryption_key:
                # If no key was set, create a default empty state
                self.passwords_data = []
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize password manager: {e}")
            self.passwords_data = []
    
    def verify_master_password(self):
        """Verify master password to decrypt existing data"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Enter Master Password")
        dialog.geometry("400x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Enter Master Password", font=("Arial", 12, "bold")).pack(pady=(0, 20))
        
        password_var = tk.StringVar()
        
        ttk.Label(frame, text="Master password:").pack(anchor=tk.W)
        password_entry = ttk.Entry(frame, textvariable=password_var, show="*")
        password_entry.pack(fill=tk.X, pady=(5, 20))
        
        def verify_and_load():
            try:
                # Try to derive key and decrypt data
                self.encryption_key = self.derive_key(password_var.get())
                self.load_passwords()
                # Refresh the UI after successful decryption
                self.refresh_password_list()
                self.update_status()
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Incorrect master password or corrupted data: {e}")
                password_var.set('')
                password_entry.focus()
        
        ttk.Button(frame, text="Unlock", command=verify_and_load).pack(pady=(0, 10))
        
        # Focus on password entry
        password_entry.focus()
        password_entry.bind('<Return>', lambda e: verify_and_load())
    
    def create_master_password(self):
        """Create a new master password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Set Master Password")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        frame = ttk.Frame(dialog, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Create Master Password", font=("Arial", 12, "bold")).pack(pady=(0, 20))
        
        password_var = tk.StringVar()
        confirm_var = tk.StringVar()
        
        ttk.Label(frame, text="Enter master password:").pack(anchor=tk.W)
        password_entry = ttk.Entry(frame, textvariable=password_var, show="*")
        password_entry.pack(fill=tk.X, pady=(5, 10))
        
        ttk.Label(frame, text="Confirm master password:").pack(anchor=tk.W)
        confirm_entry = ttk.Entry(frame, textvariable=confirm_var, show="*")
        confirm_entry.pack(fill=tk.X, pady=(5, 20))
        
        def validate_and_save():
            try:
                if password_var.get() != confirm_var.get():
                    messagebox.showerror("Error", "Passwords do not match!")
                    return
                
                if len(password_var.get()) < 8:
                    messagebox.showerror("Error", "Password must be at least 8 characters long!")
                    return
                
                self.master_password_hash = self.hash_password(password_var.get())
                self.encryption_key = self.derive_key(password_var.get())
                self.save_passwords()  # Save empty data with new master password
                # Refresh the UI after creating master password
                self.refresh_password_list()
                self.update_status()
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create master password: {e}")
        
        ttk.Button(frame, text="Set Password", command=validate_and_save).pack(pady=(0, 10))
        
        # Focus on password entry
        password_entry.focus()
        password_entry.bind('<Return>', lambda e: confirm_entry.focus())
        confirm_entry.bind('<Return>', lambda e: validate_and_save())
        
        # Add keyboard shortcuts
        self.root.bind('<Control-g>', lambda e: self.generate_password())
        self.root.bind('<Control-G>', lambda e: self.generate_password())
    
    def hash_password(self, password):
        """Create SHA-256 hash of password"""
        try:
            return hashlib.sha256(password.encode()).hexdigest()
        except Exception as e:
            raise ValueError(f"Password hashing failed: {e}")
    
    def derive_key(self, password):
        """Derive 32-byte key from password using SHA-256"""
        try:
            # Use SHA-256 hash as the key (32 bytes)
            return hashlib.sha256(password.encode()).digest()
        except Exception as e:
            raise ValueError(f"Key derivation failed: {e}")
    
    def encrypt_data(self, data):
        """Encrypt data using AES-256-CBC"""
        if not self.encryption_key:
            raise ValueError("Encryption key not set")
        
        try:
            # Generate random IV
            iv = secrets.token_bytes(16)
            
            # Create cipher
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            
            # Encrypt data
            padded_data = pad(json.dumps(data).encode(), AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            # Combine IV and encrypted data
            return base64.b64encode(iv + encrypted_data).decode()
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data using AES-256-CBC"""
        if not self.encryption_key:
            raise ValueError("Encryption key not set")
        
        try:
            # Decode from base64
            data = base64.b64decode(encrypted_data.encode())
            
            # Check minimum data length
            if len(data) < 17:  # IV (16) + at least 1 byte of encrypted data
                raise ValueError("Encrypted data too short")
            
            # Extract IV and encrypted data
            iv = data[:16]
            encrypted_data = data[16:]
            
            # Create cipher
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            
            # Decrypt data
            decrypted_data = cipher.decrypt(encrypted_data)
            unpadded_data = unpad(decrypted_data, AES.block_size)
            
            return json.loads(unpadded_data.decode())
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def save_passwords(self):
        """Save passwords to encrypted file"""
        try:
            if not self.encryption_key:
                messagebox.showerror("Error", "Encryption key not set")
                return
                
            encrypted_data = self.encrypt_data(self.passwords_data)
            with open(self.encryption_file, 'w') as f:
                f.write(encrypted_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save passwords: {e}")
    
    def load_passwords(self):
        """Load passwords from encrypted file"""
        if not os.path.exists(self.encryption_file):
            self.passwords_data = []
            return
        
        try:
            with open(self.encryption_file, 'r') as f:
                encrypted_data = f.read()
            
            if not encrypted_data.strip():
                self.passwords_data = []
                return
                
            self.passwords_data = self.decrypt_data(encrypted_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load passwords: {e}")
            self.passwords_data = []
    
    def refresh_password_list(self):
        """Refresh the password list display"""
        try:
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Add items
            for password_data in self.passwords_data:
                self.tree.insert('', tk.END, values=(
                    password_data.get('login', ''),
                    '*' * len(password_data.get('password', '')),
                    password_data.get('comment', '')
                ), tags=('password_row',))
        except Exception as e:
            # Silently handle refresh errors
            pass
    
    def save_password(self):
        """Save current password entry"""
        try:
            login = self.login_var.get().strip()
            password = self.password_var.get()
            comment = self.comment_var.get().strip()
            
            if not login or not password:
                messagebox.showwarning("Warning", "Login and password are required!")
                return
            
            # Check if login already exists
            existing_index = None
            for i, data in enumerate(self.passwords_data):
                if data.get('login') == login:
                    existing_index = i
                    break
            
            password_data = {
                'login': login,
                'password': password,
                'comment': comment
            }
            
            if existing_index is not None:
                # Update existing entry
                self.passwords_data[existing_index] = password_data
                messagebox.showinfo("Success", "Password updated successfully!")
            else:
                # Add new entry
                self.passwords_data.append(password_data)
                messagebox.showinfo("Success", "Password saved successfully!")
            
            self.save_passwords()
            self.refresh_password_list()
            self.clear_fields()
            self.update_status()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {e}")
    
    def clear_fields(self):
        """Clear input fields"""
        try:
            self.login_var.set('')
            self.password_var.set('')
            self.comment_var.set('')
        except Exception as e:
            # Silently handle clear fields errors
            pass
    
    def generate_password(self):
        """Generate a random password based on user preferences"""
        try:
            length = self.gen_length_var.get()
            use_uppercase = self.gen_uppercase_var.get()
            use_digits = self.gen_digits_var.get()
            use_symbols = self.gen_symbols_var.get()
            
            # Build character set
            chars = string.ascii_lowercase
            if use_uppercase:
                chars += string.ascii_uppercase
            if use_digits:
                chars += string.digits
            if use_symbols:
                chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
            if not chars:
                messagebox.showwarning("Warning", "Please select at least one character type!")
                return
            
            # Generate password
            password = ''.join(secrets.choice(chars) for _ in range(length))
            
            # Ensure password meets requirements
            if use_uppercase and not any(c.isupper() for c in password):
                password = secrets.choice(string.ascii_uppercase) + password[1:]
            if use_digits and not any(c.isdigit() for c in password):
                password = password[:-1] + secrets.choice(string.digits)
            if use_symbols and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                password = password[:-1] + secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
            
            self.password_var.set(password)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {e}")
    
    def use_generated_password(self):
        """Use the generated password in the password field"""
        try:
            # Generate a new password and use it
            self.generate_password()
        except Exception as e:
            # Silently handle use generated password errors
            pass
    
    def toggle_password_visibility(self, entry):
        """Toggle password field visibility"""
        try:
            if self.show_password_var.get():
                entry.config(show="")
            else:
                entry.config(show="*")
        except Exception as e:
            # Silently handle toggle visibility errors
            pass
    
    def search_passwords(self, event=None):
        """Search passwords by login or comment"""
        try:
            search_term = self.search_var.get().lower()
            
            # Clear current display
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Filter and display results
            for password_data in self.passwords_data:
                login = password_data.get('login', '').lower()
                comment = password_data.get('comment', '').lower()
                
                if search_term in login or search_term in comment:
                    self.tree.insert('', tk.END, values=(
                        password_data.get('login', ''),
                        '*' * len(password_data.get('password', '')),
                        password_data.get('comment', '')
                    ))
        except Exception as e:
            # Silently handle search errors
            pass
    
    def clear_search(self):
        """Clear search and show all passwords"""
        try:
            self.search_var.set('')
            self.refresh_password_list()
        except Exception as e:
            # Silently handle clear search errors
            pass
    
    def get_selected_item(self):
        """Get the currently selected item"""
        try:
            selection = self.tree.selection()
            if not selection:
                messagebox.showwarning("Warning", "Please select an item first!")
                return None
            
            item = self.tree.item(selection[0])
            login = item['values'][0]
            
            # Find corresponding data
            for password_data in self.passwords_data:
                if password_data.get('login') == login:
                    return password_data
            
            return None
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get selected item: {e}")
            return None
    
    def edit_selected(self):
        """Edit the selected password entry"""
        try:
            password_data = self.get_selected_item()
            if not password_data:
                return
            
            # Fill fields with selected data
            self.login_var.set(password_data.get('login', ''))
            self.password_var.set(password_data.get('password', ''))
            self.comment_var.set(password_data.get('comment', ''))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to edit selected item: {e}")
    
    def delete_selected(self):
        """Delete the selected password entry"""
        try:
            password_data = self.get_selected_item()
            if not password_data:
                return
            
            # Confirm deletion
            result = messagebox.askyesno("Confirm Delete", 
                                       f"Are you sure you want to delete the password for '{password_data.get('login')}'?")
            if not result:
                return
            
            # Remove from data
            self.passwords_data = [data for data in self.passwords_data 
                                 if data.get('login') != password_data.get('login')]
            
            self.save_passwords()
            self.refresh_password_list()
            self.update_status()
            messagebox.showinfo("Success", "Password deleted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete selected item: {e}")
    
    def on_item_double_click(self, event):
        """Handle double-click on list item"""
        try:
            self.edit_selected()
        except Exception as e:
            # Silently handle double-click errors
            pass
    
    def show_context_menu(self, event):
        """Show context menu on right-click"""
        try:
            # Select the item under cursor
            item = self.tree.identify_row(event.y)
            if item:
                self.tree.selection_set(item)
                self.context_menu.post(event.x_root, event.y_root)
        except Exception as e:
            # Silently handle context menu errors
            pass
    
    def copy_field(self, field_type):
        """Copy specific field to clipboard"""
        if pyperclip is None:
            messagebox.showwarning("Warning", "Clipboard operations are not available. Please install pyperclip.")
            return
            
        password_data = self.get_selected_item()
        if not password_data:
            return
        
        value = password_data.get(field_type, '')
        if value:
            try:
                pyperclip.copy(value)
                messagebox.showinfo("Success", f"{field_type.capitalize()} copied to clipboard!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to copy to clipboard: {e}")
    
    def toggle_password_display(self):
        """Toggle password visibility in the list for selected item"""
        try:
            password_data = self.get_selected_item()
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
                    current_values[2]
                )
            else:
                # Hide password
                new_values = (
                    current_values[0],
                    '*' * len(password_data.get('password', '')),
                    current_values[2]
                )
            
            self.tree.item(item, values=new_values)
        except Exception as e:
            # Silently handle toggle errors
            pass
    
    def update_status(self):
        """Update status bar with current information"""
        try:
            if hasattr(self, 'status_var') and hasattr(self, 'count_var'):
                count = len(self.passwords_data)
                self.count_var.set(f"{count} password{'s' if count != 1 else ''}")
                self.status_var.set("Ready")
        except Exception as e:
            # Silently handle status update errors
            pass
    
    def sort_treeview(self, col):
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
            # Silently handle sorting errors
            pass
    
    def run(self):
        """Start the application"""
        try:
            if hasattr(self, 'root') and self.root:
                self.root.mainloop()
        except Exception as e:
            messagebox.showerror("Error", f"Application failed to run: {e}")

if __name__ == "__main__":
    try:
        app = PasswordManager()
        app.run()
    except Exception as e:
        print(f"Failed to start password manager: {e}")
        input("Press Enter to exit...") 