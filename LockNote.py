from tkinterdnd2 import DND_FILES, TkinterDnD
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import platform
import shutil
import gnupg
from modification_tracker import ModificationTracker
from file_handler import FileHandler

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
        self.text = tk.Text(root, wrap="word", undo=True)
        self.text.pack(expand=True, fill="both")

        self.status = tk.Label(root, text="", anchor="w")
        self.status.pack(fill="x")

        self.mod_tracker = ModificationTracker(self.text.get("1.0", "end-1c"))
        self.file_info = FileInfo()
        self.file_handler = FileHandler(gpg)

        self.is_mac = platform.system() == "Darwin"
        self.modifier = "Command" if self.is_mac else "Control"

        icon_path = "icon.ico" # or .icns for macOS
        if os.path.exists(icon_path) and not self.is_mac:
            root.iconbitmap(icon_path)

        # Override default Text widget behavior for Undo/Redo
        self.text.bind_class("Text", "<<Undo>>", self.on_undo_event)
        self.text.bind_class("Text", "<<Redo>>", self.on_redo_event)

        self.create_menu()
        self.bind_shortcuts()
        self.bind_drag_and_drop()
        self.text.bind("<<Modified>>", self.on_text_modified)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.update_title()

        if not gpg:
            self.status.config(text="Warning: GPG not available — .gpg files won't work")

    def update_title(self):
        title = "LockNote"
        if self.file_info.path:
            title = f"LockNote — {os.path.basename(self.file_info.path)}"
        if self.mod_tracker.is_modified():
            title += " *"
        self.root.title(title)

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
        redo_accelerator = f"{self.modifier}+Shift+Z" if self.is_mac else f"{self.modifier}+Y"
        editmenu.add_command(label="Undo", command=self.undo, accelerator=f"{self.modifier}+Z")
        editmenu.add_command(label="Redo", command=self.redo, accelerator=redo_accelerator)
        editmenu.add_separator()
        editmenu.add_command(label="Cut", command=lambda: self.text.event_generate("<<Cut>>"), accelerator=f"{self.modifier}+X")
        editmenu.add_command(label="Copy", command=lambda: self.text.event_generate("<<Copy>>"), accelerator=f"{self.modifier}+C")
        editmenu.add_command(label="Paste", command=lambda: self.text.event_generate("<<Paste>>"), accelerator=f"{self.modifier}+V")
        editmenu.add_separator()
        editmenu.add_command(label="Select All", command=lambda: self.text.event_generate("<<SelectAll>>"), accelerator=f"{self.modifier}+A")
        menubar.add_cascade(label="Edit", menu=editmenu)

    def bind_shortcuts(self):
        self.root.bind_all(f"<{self.modifier}-n>", lambda e: self.new_file() or "break")
        self.root.bind_all(f"<{self.modifier}-o>", lambda e: self.open_file() or "break")
        self.root.bind_all(f"<{self.modifier}-s>", lambda e: self.save_existing_file() or "break")
        self.root.bind_all(f"<{self.modifier}-Shift-S>", lambda e: self.save_file() or "break")
        self.root.bind_all(f"<{self.modifier}-q>", lambda e: self.on_closing() or "break")

        # Edit shortcuts (Tkinter handles these by default, but explicit binding can be clearer)
        # We don't bind undo/redo here to avoid conflicts.
        self.root.bind_all(f"<{self.modifier}-x>", lambda e: self.text.event_generate("<<Cut>>") or "break")
        self.root.bind_all(f"<{self.modifier}-a>", lambda e: self.text.event_generate("<<SelectAll>>") or "break")

    def bind_drag_and_drop(self):
        self.text.drop_target_register(DND_FILES)
        self.text.dnd_bind('<<Drop>>', self.on_drop)

    def on_drop(self, event):
        path = event.data.strip("{}")
        if os.path.isfile(path):
            self.root.after(100, lambda: self.open_file_from_path(path))

    def on_text_modified(self, event=None):
        # This flag is set by Tkinter's undo/redo stack.
        # We use it to trigger our own, more robust check.
        if self.text.edit_modified():
            self.check_modified_status()
            self.text.edit_modified(False)  # Reset internal flag

    def check_modified_status(self):
        was_modified = self.mod_tracker.is_modified()
        is_modified_now = self.mod_tracker.check(self.text.get("1.0", "end-1c"))
        if was_modified != is_modified_now:
            self.update_title()

    def undo(self):
        try:
            self.text.edit_undo()
            self.check_modified_status()
        except tk.TclError:
            pass # Undo stack is empty

    def redo(self):
        try:
            self.text.edit_redo()
            self.check_modified_status()
        except tk.TclError:
            pass # Redo stack is empty

    def on_undo_event(self, event):
        self.undo()
        return "break"

    def on_redo_event(self, event):
        self.redo()
        return "break"
    
    def on_closing(self):
        if self.prompt_save_if_modified():
            self.root.destroy()

    def ask_password(self):
        dialog = PasswordDialog(self.root, title="Enter Password")
        return dialog.result

    def prompt_save_if_modified(self):
        if not self.mod_tracker.is_modified():
            return True  # Continue action

        response = messagebox.askyesnocancel(
            "Save Changes?",
            "You have unsaved changes. Do you want to save them before proceeding?",
            parent=self.root
        )

        if response is True:  # Yes
            self.save_existing_file()
            return not self.mod_tracker.is_modified() # Continue if save was successful
        elif response is False:  # No
            return True # Continue without saving
        else:  # Cancel
            return False # Abort action

    def new_file(self):
        if not self.prompt_save_if_modified():
            return

        self.text.delete("1.0", tk.END)
        self.mod_tracker.reset(self.text.get("1.0", "end-1c"))
        self.text.edit_modified(False)
        self.file_info = FileInfo()
        self.update_title()
        self.status.config(text="New file")
        self.text.edit_reset() # Clear undo/redo stack

    def open_file(self):
        if not self.prompt_save_if_modified():
            return
        path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc *.gpg")])
        if path:
            self.open_file_from_path(path)

    def open_file_from_path(self, path):
        pw = self.ask_password()
        if pw is None:
            return
        try:
            content, file_type = self.file_handler.read_file(path, pw)
            self.file_info.type = file_type

            self.text.delete("1.0", tk.END)
            self.text.insert(tk.END, content)

            self.mod_tracker.reset(content)
            self.text.edit_modified(False)
            self.file_info.path = path
            self.update_title()
            self.status.config(text=f"The file is decrypted: {path}")
            self.text.edit_reset() # Clear undo/redo stack
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self.root)

    def encrypt_and_save(self, path, password, file_type):
        plaintext = self.text.get("1.0", "end-1c")
        self.file_handler.write_file(path, plaintext, password)
        self.file_info.path = path
        self.file_info.type = file_type
        self.mod_tracker.reset(self.text.get("1.0", "end-1c"))
        self.text.edit_modified(False)
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