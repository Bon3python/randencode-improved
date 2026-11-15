"""
RandEncode - A modular arithmetic encryption tool.

Provides secure, key-based text encryption with time-lock support.
No external cryptographic dependencies required.
"""

from randencode.core import (
    RandEncodeEngine, 
    KeyManager, 
    EncryptionError, 
    generate_secure_key,
    encrypt,
    decrypt,
)

__version__ = "1.0.0"
__author__ = "starkkiv"

__all__ = [
    "RandEncodeEngine",
    "KeyManager", 
    "EncryptionError",
    "generate_secure_key",
    "encrypt",
    "decrypt",
]