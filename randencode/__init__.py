"""
RandEncode - Multi-layer modular arithmetic encryption with time-lock.

An improved version of the original RandEncode project with:
- Fixed package structure and imports
- Comprehensive error handling and input validation
- Optimized algorithms for better performance
- Better documentation and maintainability

MIT License - Copyright 2026 starkkiv (improved by Bon3python)
"""

from .core import (
    encrypt,
    decrypt,
    mod_inverse,
    extended_gcd,
    ExtendedEuclideanError,
    RandEncodeError,
    __version__
)

try:
    from .cli import interactive_mode, encrypt_cli, decrypt_cli
except ImportError as e:
    print(f"Warning: CLI module not available - {e}")
    interactive_mode = None
    encrypt_cli = None
    decrypt_cli = None

__all__ = ['encrypt', 'decrypt', 'mod_inverse', 'extended_gcd', 
           'ExtendedEuclideanError', 'RandEncodeError', '__version__',
           'interactive_mode', 'encrypt_cli', 'decrypt_cli']
