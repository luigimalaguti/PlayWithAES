from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from .data import Data
from .debug import Debug, Format


class DataInputError(Exception):
    def __init__(self, message = "Error input AES data", errors = None):
        super().__init__(message)
        self.errors = errors


class AESCipher:
    def __init__(self, **args):
        """
        Args:
            salt : bytes string
            iter : int
            iv : bytes string
            key : bytes string
            password : string
        """
        self._check_args(**args)

        self._salt = Data()
        self._iv = Data()
        self._key = Data()

        self._block_size = AES.block_size

        self._set_data(**args)
        self._build_key(**args)

        Debug.print(Format.TEXT, "")
        Debug.print(Format.TEXT, "--- INIT ---")
        Debug.print(Format.BYTES, f"Salt bytes: {self.salt.byte}")
        Debug.print(Format.HEX, f"Salt hex: {self.salt.hex}")
        Debug.print(Format.BASE64, f"Salt base64: {self.salt.base64}")
        Debug.print(Format.BYTES, f"IV bytes: {self.iv.byte}")
        Debug.print(Format.HEX, f"IV hex: {self.iv.hex}")
        Debug.print(Format.BASE64, f"IV base64: {self.iv.base64}")
        Debug.print(Format.BYTES, f"Key bytes: {self.key.byte}")
        Debug.print(Format.HEX, f"Key hex: {self.key.hex}")
        Debug.print(Format.BASE64, f"Key base64: {self.key.base64}")
        Debug.print(Format.TEXT, "")

    def _check_args(self, **args):
        # PASSWORD XNOR KEY
        password = (not args.get("password", None)) and args.get("key", None)
        key =  args.get("password", None) and (not args.get("key", None))
        if not (password or key):
            raise DataInputError("You only need to enter one of PASSWORD and KEY")

    def _set_data(self, **args):
        self._iter = args["iter"] if args.get("iter", None) else 10000
        self._salt.byte = args["salt"] if args.get("salt", None) else get_random_bytes(self.block_size)
        self._iv.byte = args["iv"] if args.get("iv", None) else get_random_bytes(self.block_size)

    def _build_key(self, **args):
        self._key.byte = args["key"] if args.get("key", None) else self._pbkdf2(**args)

    def _pbkdf2(self, **args):
        key = PBKDF2(args["password"], self.salt.byte, dkLen = 32, count = self.iter, hmac_hash_module = SHA256)
        return key

    def encrypt(self, clear_message):
        cipher = AES.new(self.key.byte, AES.MODE_CBC, self.iv.byte)
        pad_clear_message = pad(clear_message.encode(), self.block_size)
        encrypted_message = Data()
        encrypted_message.byte = cipher.encrypt(pad_clear_message)

        Debug.print(Format.TEXT, "")
        Debug.print(Format.TEXT, "--- ENCRYPT ---")
        Debug.print(Format.TEXT, f"Clear message: {clear_message}")
        Debug.print(Format.TEXT, f"Pad clear message: {pad_clear_message}")
        Debug.print(Format.BYTES, f"Encrypted message bytes: {encrypted_message.byte}")
        Debug.print(Format.HEX, f"Encrypted message hex: {encrypted_message.hex}")
        Debug.print(Format.BASE64, f"Encrypted message base64: {encrypted_message.base64}")
        Debug.print(Format.TEXT, "")

        return encrypted_message

    def decrypt(self, encrypted_message):
        cipher = AES.new(self.key.byte, AES.MODE_CBC, self.iv.byte)
        pad_clear_message = cipher.decrypt(encrypted_message.byte)
        clear_message = unpad(pad_clear_message, self.block_size)
        clear_message = clear_message.decode()

        Debug.print(Format.TEXT, "")
        Debug.print(Format.TEXT, "--- DECRYPT ---")
        Debug.print(Format.BYTES, f"Encrypted message bytes: {encrypted_message.byte}")
        Debug.print(Format.HEX, f"Encrypted message hex: {encrypted_message.hex}")
        Debug.print(Format.BASE64, f"Encrypted message base64: {encrypted_message.base64}")
        Debug.print(Format.TEXT, f"Pad clear message: {pad_clear_message}")
        Debug.print(Format.TEXT, f"Clear message: {clear_message}")
        Debug.print(Format.TEXT, "")

        return clear_message

    @property
    def block_size(self):
        return self._block_size

    @property
    def iter(self):
        return self._iter

    @property
    def salt(self):
        return self._salt

    @property
    def iv(self):
        return self._iv

    @property
    def key(self):
        return self._key
