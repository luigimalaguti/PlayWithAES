from enum import Enum


class Format(Enum):
    NONE = None
    TEXT = "text"
    BYTES = "bytes"
    HEX = "hex"
    BASE64 = "base64"


class Debug:
    DEBUG = False
    FORMAT = Format.HEX

    @staticmethod
    def print(format, message):
        if Debug.DEBUG and format == Debug.FORMAT:
            print(message)
        elif Debug.DEBUG and format == Format.TEXT:
            print(message)
        elif Debug.DEBUG and Debug.FORMAT == Format.NONE:
            print(message)
