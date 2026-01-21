# Password Manager

Desktop password manager built with Python and Tkinter. It uses AES-256-CBC
encryption and PBKDF2-HMAC-SHA256 for key derivation.

## Features

- Master password gate and encrypted local storage
- Add, edit, delete, and search entries
- Clipboard copy for login/password/comment
- Password generator with length and character options
- Auto-lock after inactivity

## Requirements

- Python 3.7+
- Windows 10/11 (tested)

## Install

Option A: automatic
```bash
python install_dependencies.py
```

Option B: manual
```bash
pip install -r requirements.txt
```

## Run

Recommended launcher:
```bash
python run_password_manager.py
```

Direct entrypoint:
```bash
python password_manager_improved.py
```

## File layout

```
auto_lock.py
constants.py
encryption.py
install_dependencies.py
logger.py
password_generator.py
password_manager.py
password_manager_improved.py
run_password_manager.py
storage.py
ui_dialogs.py
requirements.txt
requirements_improved.txt
test_functions.py
test_python.py
PasswordManager.spec
README.md
```
