from .aescipher import AESCipher
from .data import Data
from .debug import Debug, Format


def main():
    Debug.DEBUG = True
    Debug.FORMAT = Format.HEX
    
    salt = Data()
    iv = Data()
    key = Data()

    # This data are only for testing, DON'T USE THIS DATA!
    salt.hex = "39adba71259324f0292d7f6e8a734864"
    iv.hex = "e07e8c9fb7fe76f4e61b2633901be424"
    key.hex = "69942da676e537e1aa69d20c03d52ec2bca290e3f4a1f0ec89c288e93bc47e13"
    password = "password"
    
    cipher = AESCipher(iv = iv.byte, key = key.byte)

    clear_message = "Ciao"
    encrypted_message = cipher.encrypt(clear_message)

    encrypted_message.hex = "28323be59c9ae15bf5a9689bfa287ab7"
    clear_message = cipher.decrypt(encrypted_message)
