from tkinterdnd2 import DND_FILES, TkinterDnD
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import tempfile
import platform
import shutil
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import gnupg

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

gpg_path = find_gpg_binary()
gpg = gnupg.GPG(gpgbinary=gpg_path) if gpg_path else None

# AES-GCM helpers
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext

def decrypt_data(data: bytes, password: str) -> bytes:
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

class PasswordDialog(tk.Toplevel):
    def __init__(self, parent, title="Password"):
        super().__init__(parent)
        self.transient(parent)
        self.title(title)
        self.parent = parent
        self.result = None

        tk.Label(self, text="Enter password:").pack(padx=20, pady=(10, 5))

        self.entry = tk.Entry(self, show='*', width=30)
        self.entry.pack(padx=20, pady=5)
        self.entry.focus_set()

        button_frame = tk.Frame(self)
        button_frame.pack(padx=20, pady=(5, 10))

        tk.Button(button_frame, text="OK", command=self.on_ok, default=tk.ACTIVE).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT, padx=5)

        self.bind("<Return>", self.on_ok)
        self.bind("<Escape>", self.on_cancel)

        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.geometry(f"+{parent.winfo_rootx()+50}+{parent.winfo_rooty()+50}")
        self.wait_window(self)

    def on_ok(self, event=None):
        self.result = self.entry.get()
        self.destroy()

    def on_cancel(self, event=None):
        self.result = None
        self.destroy()

class FileInfo:
    def __init__(self):
        self.path = None
        self.type = None  # "enc" or "gpg"

class EncryptedEditorApp:
    def __init__(self, root):
        self.root = root
        self.text = tk.Text(root, wrap="word")
        self.text.pack(expand=True, fill="both")

        self.status = tk.Label(root, text="", anchor="w")
        self.status.pack(fill="x")

        self.file_info = FileInfo()

        self.is_mac = platform.system() == "Darwin"
        self.modifier = "Command" if self.is_mac else "Control"

        icon_path = "icon.ico" # or .icns for macOS
        if os.path.exists(icon_path) and not self.is_mac:
            root.iconbitmap(icon_path)

        self.create_menu()
        self.bind_shortcuts()
        self.bind_drag_and_drop()
        self.update_title()

        if not gpg:
            self.status.config(text="Warning: GPG not available — .gpg files won't work")

    def update_title(self):
        if self.file_info.path:
            self.root.title(f"LockNote — {os.path.basename(self.file_info.path)}")
        else:
            self.root.title("LockNote")

    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File Menu
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="New", command=self.new_file, accelerator=f"{self.modifier}+N")
        filemenu.add_command(label="Open file...", command=self.open_file, accelerator=f"{self.modifier}+O")
        filemenu.add_command(label="Save", command=self.save_existing_file, accelerator=f"{self.modifier}+S")
        filemenu.add_command(label="Save As...", command=self.save_file, accelerator=f"{self.modifier}+Shift+S")
        filemenu.add_separator()
        filemenu.add_command(label="Quit", command=self.root.quit, accelerator=f"{self.modifier}+Q")
        menubar.add_cascade(label="File", menu=filemenu)

        # Edit Menu
        editmenu = tk.Menu(menubar, tearoff=0)
        editmenu.add_command(label="Cut", command=lambda: self.text.event_generate("<<Cut>>"), accelerator=f"{self.modifier}+X")
        editmenu.add_command(label="Copy", command=lambda: self.text.event_generate("<<Copy>>"), accelerator=f"{self.modifier}+C")
        editmenu.add_command(label="Paste", command=lambda: self.text.event_generate("<<Paste>>"), accelerator=f"{self.modifier}+V")
        editmenu.add_separator()
        editmenu.add_command(label="Select All", command=lambda: self.text.event_generate("<<SelectAll>>"), accelerator=f"{self.modifier}+A")
        menubar.add_cascade(label="Edit", menu=editmenu)

    def bind_shortcuts(self):
        self.root.bind_all(f"<{self.modifier}-n>", lambda e: self.new_file())
        self.root.bind_all(f"<{self.modifier}-o>", lambda e: self.open_file())
        self.root.bind_all(f"<{self.modifier}-s>", lambda e: self.save_existing_file())
        self.root.bind_all(f"<{self.modifier}-Shift-S>", lambda e: self.save_file())
        self.root.bind_all(f"<{self.modifier}-q>", lambda e: self.root.quit())
        # Edit shortcuts (Tkinter handles these by default, but explicit binding can be clearer)
        self.root.bind_all(f"<{self.modifier}-x>", lambda e: self.text.event_generate("<<Cut>>"))
        self.root.bind_all(f"<{self.modifier}-a>", lambda e: self.text.event_generate("<<SelectAll>>"))

    def bind_drag_and_drop(self):
        self.text.drop_target_register(DND_FILES)
        self.text.dnd_bind('<<Drop>>', self.on_drop)

    def on_drop(self, event):
        path = event.data.strip("{}")
        if os.path.isfile(path):
            self.root.after(100, lambda: self.open_file_from_path(path))

    def ask_password(self):
        dialog = PasswordDialog(self.root, title="Enter Password")
        return dialog.result

    def new_file(self):
        self.text.delete("1.0", tk.END)
        self.file_info = FileInfo()
        self.update_title()
        self.status.config(text="New file")

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc *.gpg")])
        if path:
            self.open_file_from_path(path)

    def open_file_from_path(self, path):
        pw = self.ask_password()
        if pw is None:
            return
        try:
            if path.endswith(".enc"):
                with open(path, "rb") as f:
                    data = f.read()
                try:
                    decrypted = decrypt_data(data, pw)
                    content = decrypted.decode()
                except Exception:
                    raise Exception("Decryption error")
                self.file_info.type = "enc"
            elif path.endswith(".gpg"):
                if not gpg:
                    raise Exception("GPG is not available on this system.")
                with open(path, "rb") as f:
                    result = gpg.decrypt_file(f, passphrase=pw)
                if not result.ok or not result.data:
                    raise Exception(result.status or "Decryption error")
                content = result.data.decode()
                self.file_info.type = "gpg"
            else:
                raise Exception("Unsupported file format")

            self.text.delete("1.0", tk.END)
            self.text.insert(tk.END, content)
            self.file_info.path = path
            self.update_title()
            self.status.config(text=f"The file is decrypted: {path}")
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.root)

    def encrypt_and_save(self, path, password, file_type):
        plaintext = self.text.get("1.0", tk.END)
        if file_type == "enc":
            encrypted = encrypt_data(plaintext.encode(), password)
            with open(path, "wb") as f:
                f.write(encrypted)
        elif file_type == "gpg":
            if not gpg:
                raise Exception("GPG is not available on this system.")
            with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8") as tmp:
                tmp.write(plaintext)
                tmp_path = tmp.name
            with open(tmp_path, "rb") as tmp_file:
                result = gpg.encrypt_file(
                    tmp_file,
                    recipients=None,
                    symmetric='AES256',
                    passphrase=password,
                    output=path
                )
            os.unlink(tmp_path)
            if not result.ok:
                raise Exception(result.status)
        else:
            raise Exception("Unknown file type")

        self.file_info.path = path
        self.file_info.type = file_type
        self.update_title()
        self.status.config(text=f"The file is saved: {path}")

    def save_existing_file(self):
        if self.file_info.path:
            pw = self.ask_password()
            if pw is None:
                return
            try:
                self.encrypt_and_save(self.file_info.path, pw, self.file_info.type)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self.root)
        else:
            self.save_file()

    def save_file(self):
        path = filedialog.asksaveasfilename(filetypes=[("Encrypted .enc", "*.enc"), ("Encrypted .gpg", "*.gpg")], defaultextension=".enc")
        if not path:
            return
        pw = self.ask_password()
        if pw is None:
            return
        try:
            file_type = "enc" if path.endswith(".enc") else "gpg" if path.endswith(".gpg") else None
            if not file_type:
                raise Exception("Unsupported file extension")
            self.encrypt_and_save(path, pw, file_type)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.root)

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = EncryptedEditorApp(root)
    root.mainloop()