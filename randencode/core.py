"""
Core encryption/decryption logic for RandEncode.

This module implements the modular arithmetic encryption algorithm:
- Uses 4 random odd-number keys per encryption
- Applies modular multiplication (mod 256) for each layer
- Implements time-lock feature with configurable unlock time
- Supports Unicode and emoji text via UTF-8 encoding

Algorithms:
    extended_gcd(a, b): Extended Euclidean Algorithm to find GCD and Bezout's coefficients
    mod_inverse(a, m): Compute modular multiplicative inverse of a modulo m
    encrypt(text): Encrypt plaintext using 4 random keys
    decrypt(cipher_hex, keys): Decrypt ciphertext using provided keys
"""

import secrets
import time
from typing import Optional

# Configuration constants
MODULUS = 256
NUM_LAYERS = 4
DEFAULT_TIMELOCK = 72 * 60 * 60  # 72 hours in seconds

class RandEncodeError(Exception):
    """Base exception for RandEncode errors."""
    pass


class ExtendedEuclideanError(RandEncodeError):
    """Exception raised when modular inverse cannot be computed."""
    pass


def extended_gcd(a: int, b: int) -> tuple:
    """
    Extended Euclidean Algorithm.
    
    Computes the greatest common divisor of a and b,
    and the coefficients (x, y) such that ax + by = gcd(a, b).
    
    Args:
        a: First integer
        b: Second integer
        
    Returns:
        Tuple of (gcd, x, y) where gcd is the greatest common divisor
        and x, y are Bezout's coefficients.
        
    Raises:
        ValueError: If both inputs are zero
        TypeError: If inputs are not integers
    """
    if a == 0 and b == 0:
        raise ValueError("At least one of a or b must be non-zero")
    
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("Arguments must be integers")
    
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    
    return (a, x0, y0)


def mod_inverse(a: int, m: int = MODULUS) -> int:
    """
    Compute modular multiplicative inverse of a modulo m.
    
    Finds x such that (a * x) % m = 1.
    Requires gcd(a, m) = 1 (a must be coprime to m).
    
    Args:
        a: The number to find the inverse of
        m: The modulus (default: 256)
        
    Returns:
        The modular multiplicative inverse as an integer
        
    Raises:
        RandEncodeError: If inverse doesn't exist (a not coprime to m)
        TypeError: If inputs are invalid
    """
    if a < 0 or a >= m:
        raise TypeError(f"Input must be in range [0, {m})")
    
    if not isinstance(a, int):
        raise TypeError("Input must be an integer")
    
    gcd, x, _ = extended_gcd(a % m, m)
    
    if gcd != 1:
        raise ExtendedEuclideanError(
            f"Modular inverse does not exist for a={a} mod {m} "
            f"(gcd={gcd}, requires gcd=1)"
        )
    
    return x % m


def get_random_key() -> int:
    """
    Generate a random odd number in range [1, 255] that is guaranteed to be invertible mod 256.
    
    All odd numbers in this range are coprime to 256 (which is 2^8),
    so they all have modular inverses.
    
    Returns:
        A random odd integer between 1 and 255 inclusive
    """
    return secrets.choice(range(1, MODULUS, 2))


def _bytes_to_integers(data: bytes) -> list:
    """
    Convert bytes to list of integers.
    
    Optimized for batch processing by using bytearray.
    
    Args:
        data: Bytes to convert
        
    Returns:
        List of byte values as integers [0-255]
    """
    return bytearray(data)


def _integers_to_bytes(data: list) -> bytes:
    """
    Convert list of integers back to bytes.
    
    Args:
        data: List of integers [0-255]
        
    Returns:
        Bytes representation
    """
    return bytes(data)


def _apply_layer(data: list, key: int) -> list:
    """
    Apply a single encryption/decryption layer.
    
    Args:
        data: List of byte values [0-255]
        key: The multiplication key (must be coprime to MODULUS)
        is_decrypt: Whether this is decryption (uses inverse)
        
    Returns:
        Transformed list of byte values
    """
    if is_decrypt:
        inv = mod_inverse(key)
        return [(b * inv) % MODULUS for b in data]
    else:
        return [(b * key) % MODULUS for b in data]


def encrypt(text: str, unlock_time: Optional[float] = None, 
            num_layers: Optional[int] = None,
            keys: Optional[list] = None) -> dict:
    """
    Encrypt plaintext text using multi-layer modular arithmetic.
    
    Args:
        text: Plaintext string to encrypt
        unlock_time: Custom unlock timestamp (default uses 72 hours from now)
        num_layers: Number of encryption layers (default: 4)
        keys: Pre-generated keys (default: generates random odd numbers)
        
    Returns:
        Dictionary containing:
            - cipher: Hexadecimal string of encrypted bytes
            - keys: List of encryption keys used
            - unlock_time: Unix timestamp when decryption is allowed
            - num_layers: Number of layers applied
            - original_length: Original byte length (for integrity check)
            
    Raises:
        TypeError: If text is not a string or empty after stripping
        RandEncodeError: If encryption fails
    """
    if not isinstance(text, str):
        raise TypeError(f"Expected str, got {type(text).__name__}")
    
    stripped_text = text.strip()
    if not stripped_text:
        raise RandEncodeError("Cannot encrypt empty text")
    
    if num_layers is None:
        num_layers = NUM_LAYERS
    
    try:
        # Generate or use provided keys (all must be odd for invertibility)
        if keys is None:
            keys = [get_random_key() for _ in range(num_layers)]
        else:
            # Validate provided keys
            for key in keys:
                if not isinstance(key, int) or key <= 0 or key >= MODULUS:
                    raise RandEncodeError(
                        f"Invalid key: {key}. Keys must be integers in [1, {MODULUS})"
                    )
                # Ensure key is odd for guaranteed invertibility
                if key % 2 == 0:
                    raise ExtendedEuclideanError(
                        f"Key {key} is even and may not have a modular inverse mod 256. "
                        f"Please provide an odd key."
                    )
    except Exception as e:
        raise RandEncodeError(f"Failed to generate keys: {e}")
    
    # Convert text to bytes and integers
    data = _bytes_to_integers(text.encode('utf-8'))
    original_length = len(data)
    
    # Apply encryption layers sequentially
    for key in keys:
        data = _apply_layer(data, key, is_decrypt=False)
    
    # Convert back to hex string
    cipher_hex = ' '.join(f'{b:02x}' for b in data)
    
    unlock_timestamp = unlock_time or time.time() + DEFAULT_TIMELOCK
    
    return {
        'cipher': cipher_hex,
        'keys': keys,
        'unlock_time': unlock_timestamp,
        'num_layers': num_layers,
        'original_length': original_length,
        'created_at': time.time()
    }


def decrypt(cipher_hex: str, keys: list, 
            expected_length: Optional[int] = None) -> str:
    """
    Decrypt ciphertext using provided keys.
    
    Args:
        cipher_hex: Space-separated hexadecimal string of encrypted bytes
        keys: List of keys used for encryption (must be in reverse order)
        expected_length: Expected byte length of plaintext (optional integrity check)
        
    Returns:
        Decrypted plaintext string
        
    Raises:
        TypeError: If inputs have wrong types
        RandEncodeError: If decryption fails or keys are invalid
        ValueError: If ciphertext format is invalid
    """
    # Validate inputs
    if not isinstance(cipher_hex, str):
        raise TypeError(f"cipher_hex must be str, got {type(cipher_hex).__name__}")
    
    if not isinstance(keys, list) or len(keys) != NUM_LAYERS:
        raise RandEncodeError(
            f"Invalid keys: expected {NUM_LAYERS} keys, got {len(keys)}"
        )
    
    try:
        # Parse hex string
        if not cipher_hex.strip():
            raise ValueError("Cipher cannot be empty")
        
        cipher_bytes = bytearray()
        for part in cipher_hex.split():
            if len(part) != 2:
                raise ValueError(f"Invalid hex segment length: {len(part)}")
            try:
                cipher_bytes.append(int(part, 16))
            except ValueError as e:
                raise ValueError(f"Invalid hex character in cipher: {e}")
        
    except Exception as e:
        raise RandEncodeError(f"Failed to parse cipher: {e}")
    
    # Apply decryption layers (reverse order)
    for key in reversed(keys):
        try:
            data = _apply_layer(cipher_bytes, key, is_decrypt=True)
            cipher_bytes.clear()
            cipher_bytes.extend(data)
        except Exception as e:
            raise RandEncodeError(f"Decryption layer failed: {e}")
    
    # Convert to bytes and string
    try:
        decrypted_bytes = _integers_to_bytes(cipher_bytes)
        return decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        raise RandEncodeError(f"Invalid UTF-8 sequence in ciphertext: {e}")


def is_unlocked(unlock_time: float, current_time: Optional[float] = None) -> bool:
    """
    Check if time-lock has expired.
    
    Args:
        unlock_time: The unlock timestamp (Unix time)
        current_time: Current timestamp (default: now)
        
    Returns:
        True if unlocked, False otherwise
    """
    return current_time is None or current_time >= unlock_time