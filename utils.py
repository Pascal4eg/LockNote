from functools import wraps
import os
import shutil
from tkinter import messagebox

def handle_errors(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.root)
    return wrapper

def find_gpg_binary():
    candidates = [
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
        "/usr/bin/gpg",
        shutil.which("gpg"),
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None

class FileInfo:
    def __init__(self):
        self.path = None
        self.type = None  # "enc" or "gpg"
