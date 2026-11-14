#!/usr/bin/env python3
"""
Test suite for RandEncode - Validates encryption/decryption functionality.

Run this with: python test_validation.py
"""

import sys
from randencode.core import RandEncodeEngine, encrypt, decrypt, EncryptionError

def test_single_layer():
    """Test single-layer encryption/decryption."""
    engine = RandEncodeEngine()
    
    plaintext = "Hello, World!"
    result = engine.encrypt(plaintext, delay_seconds=1)
    
    # Verify cipher was generated
    assert len(result['cipher']) > 0, "Cipher should not be empty"
    assert ' ' in result['cipher'], "Cipher should be space-separated hex"
    
    # Decrypt and verify
    decrypted = engine.decrypt(list(bytes.fromhex(result['cipher'].replace(' ', ''))))
    assert plaintext == decrypted, f"Decrypted text doesn't match: {decrypted} != {plaintext}"
    print("✓ Single layer encryption/decryption test passed")

def test_multi_layer():
    """Test multi-layer encryption/decryption."""
    engine = RandEncodeEngine()
    
    for num_layers in [2, 4, 8]:
        plaintext = f"Test message with {num_layers} layers"
        result = engine.encrypt(plaintext, delay_seconds=1, num_layers=num_layers)
        
        decrypted = engine.decrypt(list(bytes.fromhex(result['cipher'].replace(' ', ''))))
        assert plaintext == decrypted, f"Failed for {num_layers} layers"
    
    print("✓ Multi-layer encryption test passed")

def test_convenience_functions():
    """Test encrypt/decrypt convenience functions."""
    plaintext = "This is a test message!"
    
    # Encrypt
    result = encrypt(plaintext)
    assert 'cipher' in result, "Result should contain 'cipher'"
    assert 'keys' in result, "Result should contain 'keys'"
    assert len(result['keys']) > 0, "Should have at least one key"
    
    # Decrypt
    decrypted = decrypt(result['cipher'], result['keys'])
    assert plaintext == decrypted, f"Decrypted: {decrypted} != Original: {plaintext}"
    print("✓ Convenience functions test passed")

def test_large_message():
    """Test encryption of large messages."""
    engine = RandEncodeEngine()
    
    # Create a message 10KB in size
    plaintext = "A" * 10240
    
    result = engine.encrypt(plaintext, delay_seconds=1)
    decrypted = engine.decrypt(list(bytes.fromhex(result['cipher'].replace(' ', ''))))
    
    assert plaintext == decrypted, "Large message failed round-trip"
    print("✓ Large message test passed (10KB)")

def test_unicode():
    """Test encryption with Unicode characters."""
    engine = RandEncodeEngine()
    
    plaintext = "Hello 世界 🌍 Привет مرحبا"
    
    result = engine.encrypt(plaintext, delay_seconds=1)
    decrypted = engine.decrypt(list(bytes.fromhex(result['cipher'].replace(' ', ''))))
    
    assert plaintext == decrypted, f"Unicode failed: {decrypted} != {plaintext}"
    print("✓ Unicode message test passed")

def test_odd_keys():
    """Test that generated keys are always odd (required for modular inverse)."""
    engine = RandEncodeEngine()
    
    for _ in range(10):
        result = engine.encrypt("test", delay_seconds=1)
        for key in result['keys']:
            assert key % 2 == 1, f"Key {key} is even (should be odd)"
    
    print("✓ Odd keys generation test passed")

def test_error_handling():
    """Test error handling."""
    engine = RandEncodeEngine()
    
    # Test decryption with wrong number of keys
    try:
        result = encrypt("test message")
        # Try decrypting with fewer keys than used
        missing_keys = result['keys'][:-1]  # Missing last key
        engine2 = RandEncodeEngine()
        engine2.key_manager.keys = missing_keys
        engine2.decrypt(list(bytes.fromhex(result['cipher'].replace(' ', ''))))
        print("✗ Should have raised error for insufficient keys")
    except (EncryptionError, ValueError):
        print("✓ Error handling test passed")

def test_time_lock():
    """Test time-lock functionality."""
    engine = RandEncodeEngine()
    
    # Set unlock time to past
    engine.key_manager.unlock_time = 0
    
    result = engine.encrypt("test", delay_seconds=3600)
    assert engine.can_decrypt(), "Should be able to decrypt with past unlock time"
    print("✓ Time-lock test passed")

def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("Running RandEncode Validation Tests")
    print("=" * 60)
    print()
    
    tests = [
        test_single_layer,
        test_multi_layer,
        test_convenience_functions,
        test_large_message,
        test_unicode,
        test_odd_keys,
        test_error_handling,
        test_time_lock,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} failed: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
        print()
    
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
