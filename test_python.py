#!/usr/bin/env python3
print("Python is working!")
print("Testing basic functionality...")

# Test imports
try:
    import tkinter
    print("✓ tkinter imported successfully")
except ImportError as e:
    print(f"✗ tkinter import failed: {e}")

try:
    import Crypto
    print("✓ pycryptodome imported successfully")
except ImportError as e:
    print(f"✗ pycryptodome import failed: {e}")

try:
    import pyperclip
    print("✓ pyperclip imported successfully")
except ImportError as e:
    print(f"✗ pyperclip import failed: {e}")

print("Test completed!") 