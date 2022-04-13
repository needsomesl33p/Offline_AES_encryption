from __future__ import annotations
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from abc import ABC, abstractmethod
from encoder import base64_encode, base64_decode


KEY_SIZES = {
    '128': 16,
    '192': 24,
    '256': 32
}

PADDING_STYLES = ['pkcs7', 'iso7816', 'x923']


class AESCryptor(ABC):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str):
        self.key = key
        self.data = data
        self.padding = padding
        self.encoding = encoding
        self._decode_key()

    @abstractmethod
    def encrypt(self) -> bytes:
        '''Encrypts input data according to the operation mode.'''
        pass

    @abstractmethod
    def decrypt(self) -> bytes:
        '''Decrypts input data with the given parameters.'''
        pass
    
    @staticmethod
    def _encryption_decorator(self, operation: function):
        def wrapper_function(*args, **kwargs):
            padded_data = self._pad_data()
            data = operation(padded_data)
            return self._encode(data)
        return wrapper_function

    def _decryption_decorator(self, operation: function, argument):
        def wrapper_function(*args, **kwargs):
            b64_decoded = self._decode(self.data)
            data = operation(argument)
            return unpad(self.data, AES.block_size, self.padding)
        return wrapper_function

    def _pad_data(self):
        return pad(self.data, AES.block_size, self.padding)

    def _unpad_data(self):
        return unpad(self.data, AES.block_size, self.padding)

    def _encode(self, data: bytes) -> bytes:
        return base64_encode(data)

    def _decode(self, data: bytes) -> bytes:
        return base64_decode(data)

    def _decode_key(self) -> None:
        if self.encoding == 'base64':
            self.key = self._decode(self.key)


class ECBCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str):
        super().__init__(key, data, padding, encoding)

    @AESCryptor._encryption_decorator
    def encrypt(self, padded_data: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(padded_data)

    @AESCryptor._decryption_decorator
    def decrypt(self) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        plaintext = cipher.decrypt(b64_decoded)
        return unpad


class CBCCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, iv: bytes):
        self.iv = iv
        super().__init__(key, data)

    def encrypt(self) -> bytes:
        print(f'CBC + {self.iv}')


suits_prototype = {
    'ECB': ECBCryptor,
    'CBC': CBCCryptor,
}

# # from Crypto.Cipher import AES
# # from Crypto.Util.Padding import pad, unpad
# # from encoder import Encoder
# # from __future__ import annotations
# # from abc import ABC, abstractmethod


# # KEY_SIZES = {
# #     '128': 16,
# #     '192': 24,
# #     '256': 32
# # }

# # PADDING_STYLES = ['pkcs7', 'iso7816', 'x923']


# # class AESEncryptor(ABC):
# #     '''
# #     Key size: 128 bits, 192 bits, 256 bites => 16 bytes, 24 bytes, 32 bytes
# #     Rounds:   10,        12        14
# #     Block size: 128 bits (fixed)
# #     '''

# #     def __init__(self, iv: bytes, key: bytes, plaintext_data: bytes, modes_of_operation: int, encoding=None):
# #         self.iv = iv
# #         self.key = key
# #         self.plaintext_data = plaintext_data
# #         self.modes_of_operation = modes_of_operation
# #         self.encoding = encoding

# #     @abstractmethod
# #     def encrypt(self) -> bytes:
# #         self._encode()

# #         AES_cipher: bytes = b''
# #         if self.iv:
# #             AES_cipher = AES.new(self.key, self.modes_of_operation, self.iv)
# #         else:
# #             AES_cipher = AES.new(self.key, self.modes_of_operation)

# #         data = Padding.box_PKCS7_padding(self.plaintext_data)
# #         encrypted_data = AES_cipher.encrypt(data)

# #         return Encoder.base64_encode(encrypted_data).pop() if self.encoding == 'none' or self.encoding == 'base64' else ''

# #     def _encode(self):
# #         if self.encoding == 'base64':
# #             result = Encoder.base64_decode(
# #                 self.iv, self.key, self.plaintext_data)
# #             self.plaintext_data = result.pop()
# #             self.key = result.pop()
# #             self.iv = result.pop()
# #         elif self.encoding == 'hex':
# #             pass


# # class AESDecryptor(object):

# #     def __init__(self, iv: bytes, key: bytes, encrypted_data: bytes, modes_of_operation: int, encoding=None):
# #         self.iv = iv
# #         self.key = key
# #         self.encrypted_data = encrypted_data
# #         self.modes_of_operation = modes_of_operation
# #         self.encoding = encoding

# #     def decrypt(self) -> bytes:
# #         self._decode_input()

# #         AES_cipher: bytes = b''
# #         if self.iv:
# #             AES_cipher = AES.new(self.key, self.modes_of_operation, self.iv)
# #         else:
# #             AES_cipher = AES.new(self.key, self.modes_of_operation)

# #         decrypted_data = AES_cipher.decrypt(self.encrypted_data)
# #         decrypted_data = Padding.unbox_PKCS7_padding(decrypted_data)
# #         return self._decode_output(decrypted_data)

# #     def _decode_input(self):
# #         if self.encoding == 'none':
# #             self.encrypted_data = Encoder.base64_decode(
# #                 self.encrypted_data).pop()
# #         elif self.encoding == 'base64':
# #             result = Encoder.base64_decode(
# #                 self.iv, self.key, self.encrypted_data)
# #             self.encrypted_data = result.pop()
# #             self.key = result.pop()
# #             self.iv = result.pop()
# #         elif self.encoding == 'hex':
# #             pass

# #     def _decode_output(self, decrypted_data: bytes) -> bytes:
# #         if self.encoding == 'base64':
# #             encoded_data = Encoder.base64_encode(decrypted_data).pop()
# #             return encoded_data
# #         else:
# #             return decrypted_data
