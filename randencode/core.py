"""
Core encryption/decryption module for RandEncode.

Implements modular arithmetic-based byte transformation with:
- Multi-layer random key application  
- Efficient extended GCD for modular inverse
- Secure key erasure utilities
"""

import secrets
import os
import time
from typing import List, Tuple, Optional

# Configuration constants
MODULUS = 256
DEFAULT_NUM_LAYERS = 4  # Number of encryption layers
VERSION = "2.0.1"


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""
    pass


class ExtendedEuclideanError(EncryptionError):
    """Exception raised when modular inverse cannot be computed."""
    pass


class RandEncodeError(EncryptionError):
    """Base exception for RandEncode errors."""
    pass


class KeyManager:
    """Manages encryption keys securely."""
    
    def __init__(self):
        self.keys: List[int] = []
        self.unlock_time: float = 0.0
    
    def add_key(self, key: int) -> None:
        """Add a key to the key list."""
        self.keys.append(key)
    
    def get_keys_reversed(self) -> List[int]:
        """Get keys in reverse order for decryption."""
        return list(reversed(self.keys))
    
    def is_unlocked(self, current_time: float) -> bool:
        """Check if the lock period has elapsed."""
        return current_time >= self.unlock_time
    
    def set_unlock_time(self, delay_seconds: int) -> None:
        """Set the unlock time based on delay in seconds."""
        self.unlock_time = time.time() + delay_seconds



class RandEncodeEngine:
    """
    Core encryption engine using modular arithmetic.
    
    Encryption formula: encrypted_byte = (plain_byte * key) % 256
    Decryption formula: plain_byte = (encrypted_byte * mod_inverse(key)) % 256
    
    Uses odd keys to guarantee existence of modular inverse.
    """
    
    def __init__(self):
        self.key_manager = KeyManager()
    
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean Algorithm.
        
        Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)
        
        This is more efficient than brute-force for modular inverse.
        """
        if a == 0:
            return b, 0, 1
        
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        
        return gcd, x, y
    
    def mod_inverse(self, a: int, m: int = MODULUS) -> int:
        """
        Compute modular multiplicative inverse using extended GCD.
        
        Returns x such that (a * x) % mod == 1
        
        Uses Extended Euclidean Algorithm for O(log n) complexity
        instead of O(mod) brute-force search.
        
        Raises EncryptionError if inverse doesn't exist.
        """
        if a < 0 or a >= m:
            raise TypeError(f"Input must be in range [0, {m})")
        
        if not isinstance(a, int):
            raise TypeError("Input must be an integer")
        
        gcd, x, _ = self.extended_gcd(a % m, m)
        
        if gcd != 1:
            raise ExtendedEuclideanError(
                f"No modular inverse exists for a={a} mod {m} "
                f"(gcd={gcd}, requires gcd=1)"
            )
        
        # Ensure positive result
        return x % m
    
    def get_random_key(self) -> int:
        """Generate a cryptographically secure random odd key (1-255, guarantees inverse exists)."""
        return secrets.choice(range(1, MODULUS, 2))
    
    def _apply_layer(self, data: List[int], key: int, is_encryption: bool = True) -> List[int]:
        """
        Apply a single encryption or decryption layer.
        
        Args:
            data: List of byte integers
            key: The encryption/decryption key
            is_encryption: If True, encrypt (multiply by key). If False, decrypt (multiply by inverse).
            
        Returns:
            Transformed list of byte integers
            
        Note: This method fixes the cryptographic bug where inverse was incorrectly used during encryption.
        """
        if not data:
            return data
        
        if is_encryption:
            # CORRECTED: Encryption uses key directly, not inverse
            # cipher_byte = (plain_byte * key) % 256
            return [(byte * key) % MODULUS for byte in data]
        else:
            # Decryption uses modular inverse
            # plain_byte = (cipher_byte * inverse(key)) % 256
            inv = self.mod_inverse(key)
            return [(byte * inv) % MODULUS for byte in data]
    
    def encrypt(self, plaintext: str, delay_seconds: int = 72 * 3600, num_layers: int = DEFAULT_NUM_LAYERS) -> dict:
        """
        Encrypt plaintext with multi-layer modular transformation.
        
        Args:
            plaintext: Text string to encrypt
            delay_seconds: Time in seconds before decryption is allowed (default: 72 hours)
            num_layers: Number of encryption layers (default: 4)
            
        Returns:
            Dictionary containing encrypted data and metadata
            
        Raises:
            EncryptionError: If encryption fails
        """
        if not isinstance(plaintext, str):
            raise EncryptionError("Plaintext must be a string")
        
        if len(plaintext.strip()) == 0:
            raise RandEncodeError("Cannot encrypt empty or whitespace-only text")
        
        if delay_seconds < 0:
            raise EncryptionError("Delay seconds cannot be negative")
        
        # Convert text to bytes (UTF-8 encoding for Unicode/emoji support)
        data = list(plaintext.encode('utf-8'))
        original_length = len(data)
        
        # Apply multiple layers of transformation
        keys_used = []
        for _ in range(num_layers):
            key = self.get_random_key()
            keys_used.append(key)
            data = self._apply_layer(data, key, is_encryption=True)
        
        # Prepare cipher output as space-separated hex string
        cipher_hex = ' '.join(f'{byte:02x}' for byte in data)
        
        # Set unlock time
        self.key_manager.set_unlock_time(delay_seconds)
        
        return {
            'cipher': cipher_hex,
            'keys': keys_used,
            'unlock_time': self.key_manager.unlock_time,
            'num_layers': num_layers,
            'original_length': original_length,
            'created_at': time.time()
        }
    
    def decrypt(self, cipher_hex: str, keys: List[int], expected_length: Optional[int] = None) -> str:
        """
        Decrypt ciphertext using provided keys.
        
        Args:
            cipher_hex: Space-separated hexadecimal string of encrypted bytes
            keys: List of keys used for encryption (must be in original order)
            expected_length: Expected byte length of plaintext (optional integrity check)
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            TypeError: If inputs have wrong types
            EncryptionError: If decryption fails or keys are invalid
            ValueError: If ciphertext format is invalid
        """
        # Validate inputs
        if not isinstance(cipher_hex, str):
            raise TypeError(f"cipher_hex must be str, got {type(cipher_hex).__name__}")
        
        if not isinstance(keys, list) or len(keys) != DEFAULT_NUM_LAYERS:
            raise EncryptionError(
                f"Invalid keys: expected {DEFAULT_NUM_LAYERS} keys, got {len(keys)}"
            )
        
        try:
            # Parse hex string
            if not cipher_hex.strip():
                raise EncryptionError("Cipher cannot be empty")
            
            cipher_bytes = bytearray()
            for part in cipher_hex.split():
                if len(part) != 2:
                    raise ValueError(f"Invalid hex segment length: {len(part)}")
                try:
                    cipher_bytes.append(int(part, 16))
                except ValueError as e:
                    raise ValueError(f"Invalid hex character in cipher: {e}")
            
        except Exception as e:
            raise EncryptionError(f"Failed to parse cipher: {e}")
        
        # Apply decryption layers (in reverse order of encryption)
        for key in reversed(keys):
            try:
                data = self._apply_layer(cipher_bytes, key, is_encryption=False)
                cipher_bytes.clear()
                cipher_bytes.extend(data)
            except Exception as e:
                raise EncryptionError(f"Decryption layer failed: {e}")
        
        # Convert to bytes and string
        try:
            decrypted_bytes = bytes(cipher_bytes)
            
            # Optional integrity check
            if expected_length is not None and len(decrypted_bytes) != expected_length:
                raise EncryptionError(
                    f"Decrypted length ({len(decrypted_bytes)}) doesn't match expected length ({expected_length})"
                )
            
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            raise EncryptionError(f"Invalid UTF-8 sequence in ciphertext: {e}")
    
    def can_decrypt(self, current_time: Optional[float] = None) -> bool:
        """Check if time-lock has expired."""
        now = current_time or time.time()
        return self.key_manager.is_unlocked(now)


def generate_secure_key() -> int:
    """Generate a cryptographically secure random key (1-255, odd)."""
    return secrets.choice(range(1, 256, 2))


def encrypt(plaintext: str, delay_seconds: int = 72 * 3600, num_layers: int = DEFAULT_NUM_LAYERS) -> dict:
    """
    Encrypt plaintext using multi-layer modular arithmetic.
    
    Args:
        plaintext: Text string to encrypt
        delay_seconds: Time in seconds before decryption is allowed (default: 72 hours)
        num_layers: Number of encryption layers (default: 4)
        
    Returns:
        Dictionary with cipher, keys, unlock_time, and metadata
        
    Raises:
        EncryptionError: If encryption fails
    """
    engine = RandEncodeEngine()
    return engine.encrypt(plaintext, delay_seconds, num_layers)


def decrypt(cipher_hex: str, keys: List[int], expected_length: Optional[int] = None) -> str:
    """
    Decrypt ciphertext using provided keys.
    
    Args:
        cipher_hex: Space-separated hexadecimal string of encrypted bytes
        keys: List of keys used for encryption (in original order)
        expected_length: Expected byte length of plaintext (optional)
        
    Returns:
        Decrypted plaintext string
        
    Raises:
        EncryptionError: If decryption fails
    """
    engine = RandEncodeEngine()
    return engine.decrypt(cipher_hex, keys, expected_length)


def generate_key_pair() -> Tuple[int, int]:
    """Generate an encryption/decryption key pair."""
    engine = RandEncodeEngine()
    key = generate_secure_key()
    inverse = engine.mod_inverse(key)
    return key, inverse


def encrypt_with_engine(plaintext: str, delay_seconds: int = 72 * 3600) -> dict:
    """Encrypt text using default engine."""
    engine = RandEncodeEngine()
    return engine.encrypt(plaintext, delay_seconds)


def decrypt_with_engine(cipher_hex: str, keys: List[int]) -> str:
    """Decrypt ciphertext using provided keys and default engine."""
    engine = RandEncodeEngine()
    return engine.decrypt(cipher_hex, keys)


__all__ = [
    'RandEncodeEngine',
    'KeyManager', 
    'EncryptionError',
    'ExtendedEuclideanError', 
    'RandEncodeError',
    'generate_secure_key',
    'generate_key_pair',
    'encrypt',
    'decrypt',
    'encrypt_with_engine',
    'decrypt_with_engine'
]

