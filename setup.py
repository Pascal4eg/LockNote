from setuptools import setup

APP = ['LockNote.py']
DATA_FILES = ['icon.icns']
OPTIONS = {
    'argv_emulation': False,
    'iconfile': 'icon.icns',
    'packages': ['tkinterdnd2', 'cryptography', 'gnupg'],
    'plist': {
        'CFBundleName': 'LockNote',
        'CFBundleDisplayName': 'LockNote',
        'CFBundleIdentifier': 'com.locknote.app',
        'CFBundleVersion': '1.0.0',
        'CFBundleShortVersionString': '1.0.0',
        'NSHighResolutionCapable': True,
    },
    'includes': ['tkinter', '_tkinter', 'tkinterdnd2', '_cffi_backend'],
}

setup(
    app=APP,
    name='LockNote',
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
