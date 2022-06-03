from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from utils import base64_encode, base64_decode


# Key size: 128 bits, 192 bits, 256 bites => 16 bytes, 24 bytes, 32 bytes
# Rounds:   10,        12        14
# Block size: 128 bits (fixed)
KEY_SIZES = {
    '128': 16,
    '192': 24,
    '256': 32
}

PADDING_STYLES = ['pkcs7', 'iso7816', 'x923']


class AESCryptor(ABC):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        self.key = key
        self.data = data
        self.padding = padding
        self.encoding = encoding
        self.kwargs = kwargs
        self._decode_key()
        self._decode_aad()
        self._decode_item('nonce')
        self._decode_item('mac')

    @abstractmethod
    def encrypt(self) -> bytes:
        '''Encrypts input data according to the operation mode.'''
        pass

    @abstractmethod
    def decrypt(self) -> bytes:
        '''Decrypts input data with the given parameters.'''
        pass

    @staticmethod
    def _encryption_decorator(operation: function):
        def wrapper_function(*args):
            _self = args[0]
            padded_data = _self._pad_data()
            data, nonce = operation(_self, padded_data)
            if nonce:
                return base64_encode(data), base64_encode(nonce), None
            return base64_encode(data), nonce, None
        return wrapper_function

    @staticmethod
    def _decryption_decorator(operation: function):
        def wrapper_function(*args):
            _self = args[0]
            b64_decoded = base64_decode(_self.data)
            data = operation(_self, b64_decoded)
            return _self._unpad_data(data)
        return wrapper_function

    @staticmethod
    def _encryption_decorator_aead(operation: function):
        def wrapper_function(*args):
            _self = args[0]
            padded_data = _self._pad_data()
            data, nonce, mac = operation(_self, padded_data)
            if nonce:
                nonce = base64_encode(nonce)
            return base64_encode(data), nonce, base64_encode(mac)
        return wrapper_function

    def _craft_aead_ciphertext(self, mode_of_operation: int, padded_data: bytes) -> Tuple[bytes, bytes]:
        aad = self.kwargs.pop('aad', None)
        cipher = AES.new(self.key, mode_of_operation, **self.kwargs)
        if aad:
            cipher.update(aad)
        ciphertext, mac = cipher.encrypt_and_digest(padded_data)
        if self.kwargs.get('nonce'):
            return ciphertext, None, mac
        return ciphertext, cipher.nonce, mac

    def _craft_aead_plaintext(self, mode_of_operation: int, ciphertext: bytes) -> bytes:
        aad = self.kwargs.pop('aad', None)
        mac = self.kwargs.pop('mac')
        cipher = AES.new(self.key, mode_of_operation, **self.kwargs)
        if aad:
            cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, mac)

    def _pad_data(self):
        return pad(self.data, AES.block_size, self.padding)

    def _unpad_data(self, data: bytes) -> bytes:
        return unpad(data, AES.block_size, self.padding)

    def _decode_key(self) -> None:
        if self.encoding == 'base64':
            self.key = base64_decode(self.key)

    def _decode_aad(self) -> None:
        value = self.kwargs.get('aad')
        if value and self.encoding == 'base64':
            self.kwargs['aad'] = base64_decode(value)

    def _decode_item(self, item: str) -> None:
        value = self.kwargs.get(item)
        if value:
            self.kwargs[item] = base64_decode(value)


class ECBCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        super().__init__(key, data, padding, encoding, **kwargs)

    @AESCryptor._encryption_decorator
    def encrypt(self, *args) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(*args), None

    @AESCryptor._decryption_decorator
    def decrypt(self, *args) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.decrypt(*args)


class CBCCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        super().__init__(key, data, padding, encoding, **kwargs)

    @AESCryptor._encryption_decorator
    def encrypt(self, *args) -> bytes:
        iv: bytes = self.kwargs.pop('nonce', None)
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        if iv:
            return cipher.encrypt(*args), None
        return cipher.encrypt(*args), cipher.iv

    @AESCryptor._decryption_decorator
    def decrypt(self, *args) -> bytes:
        iv: bytes = self.kwargs.pop('nonce')
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        return cipher.decrypt(*args)


class CFBCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        super().__init__(key, data, padding, encoding, **kwargs)

    @AESCryptor._encryption_decorator
    def encrypt(self, *args) -> bytes:
        iv: bytes = self.kwargs.pop('nonce', None)
        cipher = AES.new(self.key, AES.MODE_CFB, iv=iv, **self.kwargs)
        if iv:
            return cipher.encrypt(*args), None
        return cipher.encrypt(*args), cipher.iv

    @AESCryptor._decryption_decorator
    def decrypt(self, *args) -> bytes:
        iv: bytes = self.kwargs.pop('nonce')
        cipher = AES.new(self.key, AES.MODE_CFB, iv=iv, **self.kwargs)
        return cipher.decrypt(*args)


class OFBCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        super().__init__(key, data, padding, encoding, **kwargs)

    @AESCryptor._encryption_decorator
    def encrypt(self, *args) -> bytes:
        iv: bytes = self.kwargs.pop('nonce', None)
        cipher = AES.new(self.key, AES.MODE_OFB, iv=iv)
        if iv:
            return cipher.encrypt(*args), None
        return cipher.encrypt(*args), cipher.iv

    @AESCryptor._decryption_decorator
    def decrypt(self, *args) -> bytes:
        iv: bytes = self.kwargs.pop('nonce')
        cipher = AES.new(self.key, AES.MODE_OFB, iv=iv)
        return cipher.decrypt(*args)


class CTRCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        super().__init__(key, data, padding, encoding, **kwargs)

    @AESCryptor._encryption_decorator
    def encrypt(self, *args) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CTR, **self.kwargs)
        if self.kwargs.get('nonce'):
            return cipher.encrypt(*args), None
        return cipher.encrypt(*args), cipher.nonce

    @AESCryptor._decryption_decorator
    def decrypt(self, *args) -> bytes:
        nonce: bytes = self.kwargs.pop('nonce')
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce, **self.kwargs)
        return cipher.decrypt(*args)


class OpenPGPCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        super().__init__(key, data, padding, encoding, **kwargs)

    @AESCryptor._encryption_decorator
    def encrypt(self, *args) -> bytes:
        iv: bytes = self.kwargs.pop('nonce', None)
        cipher = AES.new(self.key, AES.MODE_OPENPGP, iv=iv)
        if iv:
            return cipher.encrypt(*args), None
        return cipher.encrypt(*args), cipher.iv

    @AESCryptor._decryption_decorator
    def decrypt(self, *args) -> bytes:
        enc_iv: bytes = args[0][:18]
        ciphertext: bytes = args[0][18:]
        cipher = AES.new(self.key, AES.MODE_OPENPGP, iv=enc_iv)
        return cipher.decrypt(ciphertext)


class CCMCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        super().__init__(key, data, padding, encoding, **kwargs)

    @AESCryptor._encryption_decorator_aead
    def encrypt(self, *args) -> bytes:
        return self._craft_aead_ciphertext(AES.MODE_CCM, *args)

    @AESCryptor._decryption_decorator
    def decrypt(self, *args) -> bytes:
        return self._craft_aead_plaintext(AES.MODE_CCM, *args)


class EAXCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        super().__init__(key, data, padding, encoding, **kwargs)

    @AESCryptor._encryption_decorator_aead
    def encrypt(self, *args) -> bytes:
        return self._craft_aead_ciphertext(AES.MODE_EAX, *args)

    @AESCryptor._decryption_decorator
    def decrypt(self, *args) -> bytes:
        return self._craft_aead_plaintext(AES.MODE_EAX, *args)


class SIVCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        super().__init__(key, data, padding, encoding, **kwargs)

    @AESCryptor._encryption_decorator_aead
    def encrypt(self, *args) -> bytes:
        return self._craft_aead_ciphertext(AES.MODE_SIV, *args)

    @AESCryptor._decryption_decorator
    def decrypt(self, *args) -> bytes:
        return self._craft_aead_plaintext(AES.MODE_SIV, *args)


class GCMCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        super().__init__(key, data, padding, encoding, **kwargs)

    @AESCryptor._encryption_decorator_aead
    def encrypt(self, *args) -> bytes:
        return self._craft_aead_ciphertext(AES.MODE_GCM, *args)

    @AESCryptor._decryption_decorator
    def decrypt(self, *args) -> bytes:
        return self._craft_aead_plaintext(AES.MODE_GCM, *args)


class OCBCryptor(AESCryptor):

    def __init__(self, key: bytes, data: bytes, padding: str, encoding: str, **kwargs):
        super().__init__(key, data, padding, encoding, **kwargs)

    @AESCryptor._encryption_decorator_aead
    def encrypt(self, *args) -> bytes:
        return self._craft_aead_ciphertext(AES.MODE_OCB, *args)

    @AESCryptor._decryption_decorator
    def decrypt(self, *args) -> bytes:
        return self._craft_aead_plaintext(AES.MODE_OCB, *args)


suits_prototype = {
    # Classic modes of operation
    'ECB': ECBCryptor,
    'CBC': CBCCryptor,
    'CFB': CFBCryptor,
    'OFB': OFBCryptor,
    'CTR': CTRCryptor,
    'OPENPGP': OpenPGPCryptor,
    # Modern modes of operation
    'CCM': CCMCryptor,
    'EAX': EAXCryptor,
    'SIV': SIVCryptor,
    'GCM': GCMCryptor,
    'OCB': OCBCryptor
}
