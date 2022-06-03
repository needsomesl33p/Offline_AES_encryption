from __future__ import annotations
import base64
import secrets
import json
from typing import Dict, List


def base64_encode(*args, **kwargs) -> str | List | Dict:
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


def base64_decode(*args, **kwargs) -> str | List | Dict:
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


def sort_dict(_dict: dict) -> None:
    cpy_dict: dict = _dict.copy()
    for key, value in cpy_dict.items():
        if not value:
            del _dict[key]


def gen_secret(size: int) -> bytes:
    return secrets.token_bytes(size)


def load_config(path: str) -> dict:
    with open(path, 'r') as file:
        return json.load(file)


def convert_byte2string(comps: dict) -> dict:
    for item, value in comps.items():
        if isinstance(value, bytes):
            comps[item] = value.decode('utf-8')
