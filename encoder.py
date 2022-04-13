import base64
import secrets
import codecs
from binascii import hexlify
from typing import Any


def base64_encode(*args, **kwargs):
    result = None

    if args:
        result = []
        for item in args:
            result.append(base64.b64encode(item))

    if kwargs:
        result = {}
        for item, value in kwargs.items():
            result[item] = base64.b64encode(value)

    return result[0] if len(result) == 1 else result


def base64_decode(*args, **kwargs) -> list or dict:
    result = None

    if args:
        result = []
        for item in args:
            result.append(base64.b64decode(item))

    if kwargs:
        result = {}
        for item, value in kwargs.items():
            result[item] = base64.b64decode(value)

    return result[0] if len(result) == 1 else result


def gen_iv(size: int) -> bytes:
    return secrets.token_bytes(size)


def hex_encode(bytes_obj: bytes) -> str:
    return hexlify(bytes_obj)


def hex_decode(hex_string: str) -> bytes:
    return codecs.decode(hex_string, 'hex_codec')
