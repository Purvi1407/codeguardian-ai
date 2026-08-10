# -*- coding: utf-8 -*-
"""Module with non-ASCII content to check the analyzer handles encoding
correctly instead of crashing on decode/index errors."""
import hashlib


def grüße(name):
    """Uses a non-ASCII identifier (valid in Python 3) and emoji in a
    string literal 😀, plus a real vulnerability nearby to
    confirm unicode content doesn't break line-number tracking."""
    message = f"Hallo, {name}! 👋"
    return message


def weak_crypto_hash__near_unicode(data):
    # The unicode content above must not shift or break detection here.
    return hashlib.md5(data).hexdigest()
