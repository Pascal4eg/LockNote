# 🔐 LockNote

**LockNote** is a simple, cross-platform text editor with strong encryption. It lets you create, open, and save encrypted text files using either AES encryption (`.enc`) or GPG (`.gpg`). Ideal for keeping sensitive notes safe on your local machine.

---

## ✨ Features

- 💾 Save and open encrypted `.enc` or `.gpg` files.
- 🔑 Password-based encryption using:
  - AES-GCM + PBKDF2 (`.enc`)
  - GPG symmetric encryption with AES256 (`.gpg`)
- 🔒 Decryption requires a password prompt.
- 🧠 Remembers the currently opened file and updates the window title.
- 🖱️ Drag and drop a file into the editor to open it.
- 🖱️ GUI built with **Tkinter** and **tkinterdnd2** for DnD support.
- 💻 Works on **Windows**, **macOS**, and **Linux**.
- 🎹 Keyboard shortcuts for New, Open, Save, Save As, and Quit.

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/Pascal4eg/LockNote.git
cd LockNote
```

### 2. Install dependencies

```bash
pip install cryptography python-gnupg tkinterdnd2
```

> Note: On macOS and Linux, you may also need to install the GPG command-line tool (`gpg`) separately:
```bash
# macOS (via Homebrew)
brew install gnupg

# Ubuntu/Debian
sudo apt install gnupg
```

---

## 🚀 Run the app

```bash
python LockNote.py
```

---

## 🖼️ Icons

LockNote includes a clean icon featuring a lock and notepad.

- `icon.ico` – used for Windows
- `icon.icns` – used when building macOS apps

---

## 🔧 Packaging

You can bundle LockNote using [`pyinstaller`](https://pyinstaller.org/) or other packagers like [`py2app`](https://py2app.readthedocs.io/en/latest/) or `nuitka`.

### Example (Windows):
```bash
pyinstaller --noconsole --onefile --icon=icon.ico LockNote.py
```

### Example (macOS):
```bash
python setup.py py2app
```

---

## 📁 File formats

- `.enc` files are encrypted using AES-GCM with a key derived from the password using PBKDF2.
- `.gpg` files use GnuPG with AES256 symmetric encryption.
- Files can be opened or saved automatically by extension.

---

## 🙌 Credits

Built with ❤️ using Python and Tkinter.
