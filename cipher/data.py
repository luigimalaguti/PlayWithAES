from base64 import b64encode, b64decode


class Byte:
    def __get__(self, instance, cls):
        return instance._byte

    def __set__(self, instance, value):
        instance._byte = value
        instance._hex = value.hex()
        instance._base64 = b64encode(value)


class Hex:
    def __get__(self, instance, cls):
        return instance._hex

    def __set__(self, instance, value):
        instance._byte = bytes.fromhex(value)
        instance._hex = value
        instance._base64 = b64encode(bytes.fromhex(value))


class Base64:
    def __get__(self, instance, cls):
        return instance._base64

    def __set__(self, instance, value):
        instance._byte = b64decode(value)
        instance._hex = b64decode(value).hex()
        instance._base64 = value


class Data:
    byte = Byte()
    hex = Hex()
    base64 = Base64()

    def __init__(self):
        self._byte = None
        self._hex = None
        self._base64 = None
        self._ascii = None
