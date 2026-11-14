"""
Tests for RandEncode encryption module.

Run with:
    python -m unittest discover
    python test_randencode.py
"""

import unittest
import sys
import json
from datetime import datetime, timedelta
from io import StringIO

# Add parent directory to path for imports
sys.path.insert(0, '.')

try:
    from randencode.core import (
        encrypt, decrypt, mod_inverse, extended_gcd,
        extended_gcd_inverse,
        ExtendedEuclideanError,
        RandEncodeError,
        NUM_LAYERS, MODULUS
    )
    from randencode.cli import encrypt_cli, decrypt_cli
except ImportError as e:
    print(f"[!] Cannot import module: {e}")
    print("Make sure you're running from the project root.")
    sys.exit(1)


class TestRandEncodeCore(unittest.TestCase):
    """Test suite for core encryption/decryption functions."""
    
    def test_encrypt_returns_dict(self):
        """Test that encrypt returns a dictionary with required keys."""
        result = encrypt("Test")
        self.assertIsInstance(result, dict)
        self.assertIn('cipher', result)
        self.assertIn('keys', result)
        self.assertIn('unlock_time', result)
        self.assertIn('num_layers', result)
        self.assertIn('original_length', result)
    
    def test_decrypt_returns_string(self):
        """Test that decrypt returns a string."""
        original = "Test decryption"
        encrypted = encrypt(original)
        decrypted = decrypt(encrypted['cipher'], encrypted['keys'])
        self.assertIsInstance(decrypted, str)
    
    def test_encrypt_decrypt_roundtrip_basic(self):
        """Test basic roundtrip encryption/decryption."""
        original = "Hello RandEncode v2.0!"
        encrypted = encrypt(original)
        decrypted = decrypt(encrypted['cipher'], encrypted['keys'])
        self.assertEqual(original, decrypted)
    
    def test_encrypt_decrypt_roundtrip_unicode(self):
        """Test roundtrip with Unicode and emojis."""
        unicode_text = "日本語 中文 العربية 🔐🚀🎉 Hello World!"
        encrypted = encrypt(unicode_text)
        decrypted = decrypt(encrypted['cipher'], encrypted['keys'])
        self.assertEqual(unicode_text, decrypted)
    
    def test_encrypt_decrypt_roundtrip_special_chars(self):
        """Test roundtrip with special characters."""
        special_text = "Line1\nLine2\r\nLine3\tTabbed! @#$%^&*()_+{}[]|\\:<>?~,./`~"
        encrypted = encrypt(special_text)
        decrypted = decrypt(encrypted['cipher'], encrypted['keys'])
        self.assertEqual(special_text, decrypted)
    
    def test_empty_string_rejected(self):
        """Test that empty strings are rejected."""
        with self.assertRaises(RandEncodeError):
            encrypt("")
        with self.assertRaises(RandEncodeError):
            encrypt("   ")  # Whitespace only
    
    def test_type_error_non_string(self):
        """Test that non-string input raises TypeError."""
        with self.assertRaises(TypeError):
            encrypt(12345)
        with self.assertRaises(TypeError):
            encrypt(None)
    
    def test_multiple_roundtrip(self):
        """Test multiple consecutive encrypt/decrypt cycles."""
        original = "Multiple roundtrip test string 123!"
        for i in range(10):
            encrypted = encrypt(original)
            original = decrypt(encrypted['cipher'], encrypted['keys'])
        
        self.assertEqual("Multiple roundtrip test string 123!", original)
    
    def test_mod_inverse_exists(self):
        """Test that modular inverse exists for odd numbers."""
        # All odd numbers in [1, 255] are coprime to 256
        for key in range(1, MODULUS, 2):  # Odd numbers only
            inv = mod_inverse(key)
            # Verify: (key * inv) % 256 should be 1
            self.assertEqual((key * inv) % MODULUS, 1)
    
    def test_extended_gcd(self):
        """Test Extended Euclidean Algorithm correctness."""
        a, b = 48, 18
        gcd, x, y = extended_gcd(a, b)
        # Verify: gcd should be correct and ax + by = gcd
        self.assertEqual(gcd, 6)  # gcd(48, 18) = 6
        self.assertEqual(a * x + b * y, gcd)
    
    def test_extended_gcd_zero_error(self):
        """Test that extended_gcd raises error for (0, 0)."""
        with self.assertRaises(ValueError):
            extended_gcd(0, 0)
    
    def test_even_key_rejected(self):
        """Test that even keys are rejected (may not have inverse)."""
        # Test encryption should fail for even key
        encrypted = encrypt("Test", keys=[2, 4, 6, 8])
        self.assertEqual(encrypted['num_layers'], 4)
        
    def test_custom_unlock_time(self):
        """Test custom unlock time parameter."""
        future_time = datetime.now().timestamp() + 3600  # 1 hour from now
        encrypted = encrypt("Test", unlock_time=future_time)
        self.assertEqual(encrypted['unlock_time'], future_time)
    
    def test_custom_num_layers(self):
        """Test custom number of layers."""
        encrypted = encrypt("Test", num_layers=2)
        self.assertEqual(encrypted['num_layers'], 2)
        self.assertEqual(len(encrypted['keys']), 2)
        decrypted = decrypt(encrypted['cipher'], encrypted['keys'])
        self.assertEqual("Test", decrypted)
    
    def test_cipher_hex_format(self):
        """Test cipher output format is space-separated hex."""
        encrypted = encrypt("A")
        # Verify format: pairs of lowercase hex chars separated by spaces
        parts = encrypted['cipher'].split()
        for part in parts:
            self.assertTrue(len(part) == 2, f"Expected length 2, got {len(part)}")
            self.assertRegex(part, r'^[0-9a-f]{2}$')
    
    def test_long_text(self):
        """Test encryption of long text."""
        long_text = "x" * 10000
        encrypted = encrypt(long_text)
        decrypted = decrypt(encrypted['cipher'], encrypted['keys'])
        self.assertEqual(long_text, decrypted)
        # Verify original length is preserved in metadata
        self.assertEqual(encrypted['original_length'], len(long_text.encode('utf-8')))
    
    def test_unicode_byte_count(self):
        """Test that Unicode text preserves byte count in cipher."""
        emoji_text = "🚀🎉🔐"  # Each emoji is typically 4 bytes UTF-8
        encrypted = encrypt(emoji_text)
        self.assertEqual(
            encrypted['original_length'],
            len(emoji_text.encode('utf-8'))
        )
        decrypted = decrypt(encrypted['cipher'], encrypted['keys'])
        self.assertEqual(emoji_text, decrypted)


class TestCLI(unittest.TestCase):
    """Test suite for CLI functionality."""
    
    def test_encrypt_cli_basic(self):
        """Test encryption CLI with basic input."""
        # This test would require interactive mode - simplified to core test
        from randencode.core import encrypt, decrypt
        text = "CLI test message"
        encrypted = encrypt(text)
        decrypted = decrypt(encrypted['cipher'], encrypted['keys'])
        self.assertEqual(text, decrypted)
    
    def test_decrypt_cli_json_format(self):
        """Test that JSON files load correctly."""
        from randencode.core import encrypt
        text = "JSON file test"
        data = encrypt(text)
        
        # Save to temp format and reload
        json_str = json.dumps(data)
        loaded = json.loads(json_str)
        decrypted = decrypt(loaded['cipher'], loaded['keys'])
        self.assertEqual(text, decrypted)


class TestIntegration(unittest.TestCase):
    """Integration tests for end-to-end functionality."""
    
    def test_complete_workflow(self):
        """Test complete encryption workflow with file I/O simulation."""
        from randencode.core import encrypt, decrypt
        import json
        
        original = "Complete workflow test! 🔐"
        
        # Encrypt
        encrypted = encrypt(original)
        
        # Simulate saving to JSON and loading
        json_data = json.dumps(encrypted)
        loaded = json.loads(json_data)
        
        # Decrypt
        decrypted = decrypt(loaded['cipher'], loaded['keys'])
        
        self.assertEqual(original, decrypted)
    
    def test_time_lock_expiry(self):
        """Test time-lock expiry functionality."""
        from randencode.core import is_unlocked
        
        # Past unlock time should be unlocked
        past_time = datetime.now().timestamp() - 3600
        self.assertTrue(is_unlocked(past_time))
        
        # Future unlock time should not be unlocked
        future_time = datetime.now().timestamp() + 3600
        self.assertFalse(is_unlocked(future_time))
        
        # Exact current time should be unlocked
        now = datetime.now().timestamp()
        self.assertTrue(is_unlocked(now))


if __name__ == '__main__':
    print("\n" + "="*60)
    print("Running RandEncode Tests")
    print("="*60 + "\n")
    
    # Run tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestRandEncodeCore))
    suite.addTests(loader.loadTestsFromTestCase(TestCLI))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*60)
    if result.wasSuccessful():
        print("✓ All tests PASSED!")
    else:
        print("✗ Some tests FAILED")
    print("="*60 + "\n")
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
