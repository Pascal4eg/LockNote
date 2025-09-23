import os
import tempfile
from crypto_utils import encrypt_data, decrypt_data

class FileHandler:
    def __init__(self, gpg_instance):
        self.gpg = gpg_instance

    def read_file(self, path, password):
        file_type = self._get_file_type(path)
        if file_type == "enc":
            with open(path, "rb") as f:
                data = f.read()
            try:
                decrypted = decrypt_data(data, password)
                content = decrypted.decode()
            except Exception:
                raise Exception("Decryption error or wrong password")
            return content, "enc"
        elif file_type == "gpg":
            if not self.gpg:
                raise Exception("GPG is not available on this system.")
            with open(path, "rb") as f:
                result = self.gpg.decrypt_file(f, passphrase=password)
            if not result.ok or not result.data:
                raise Exception(result.status or "Decryption error or wrong password")
            return result.data.decode(), "gpg"
        else:
            raise Exception("Unsupported file format")

    def write_file(self, path, content, password):
        file_type = self._get_file_type(path)
        if file_type == "enc":
            encrypted = encrypt_data(content.encode(), password)
            with open(path, "wb") as f:
                f.write(encrypted)
        elif file_type == "gpg":
            if not self.gpg:
                raise Exception("GPG is not available on this system.")
            # Using a temporary file is safer for GPG operations
            with tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8") as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            with open(tmp_path, "rb") as tmp_file:
                result = self.gpg.encrypt_file(
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

    def _get_file_type(self, path):
        if path.endswith(".enc"):
            return "enc"
        if path.endswith(".gpg"):
            return "gpg"
        return None
