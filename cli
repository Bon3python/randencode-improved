"""
Command-Line Interface for RandEncode.

Provides interactive and programmatic access to encryption/decryption functionality.

Usage:
    python -m randencode                    # Interactive mode
    python -m randencode encrypt "your text"   # Quick encryption
    python -m randencode decrypt cipher.json    # Decryption from file
"""

import sys
import json
import glob
from datetime import datetime
from typing import Optional, Tuple

try:
    from .core import encrypt, decrypt, is_unlocked, RandEncodeError, ExtendedEuclideanError
except ImportError as e:
    print(f"Error: Cannot import core module - {e}")
    sys.exit(1)


def validate_json_file(filepath: str) -> Tuple[bool, str]:
    """
    Validate and load a JSON file containing encrypted data.
    
    Args:
        filepath: Path to JSON file
        
    Returns:
        Tuple of (success: bool, message: str)
    """
    import os
    
    if not os.path.exists(filepath):
        return False, f"File not found: {filepath}"
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        required_keys = ['cipher', 'keys']
        missing = [k for k in required_keys if k not in data]
        if missing:
            return False, f"Missing required fields: {', '.join(missing)}"
        
        # Validate cipher format
        if not isinstance(data['cipher'], str):
            return False, "'cipher' must be a string"
        
        # Validate keys type
        if not isinstance(data['keys'], list):
            return False, "'keys' must be a list"
        
        return True, f"Loaded successfully ({len(data['keys'])} layers)"
    
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON format: {e}"
    except Exception as e:
        return False, f"Failed to load file: {type(e).__name__}: {e}"


def encrypt_cli(args: Optional[list] = None) -> None:
    """
    Handle encryption from command line or interactive mode.
    
    Args:
        args: Optional list of command-line arguments
        
    Example:
        encrypt_cli(['"Hello World"'])
    """
    if args is None:
        # Interactive mode
        print("\n" + "="*60)
        print("       RandEncode - Multi-Layer Time-Lock Encryption")
        print("="*60)
        
        text = input("\nEnter text to encrypt: ").strip()
        
        if not text:
            print("[!] Error: Cannot encrypt empty text")
            return
        
        try:
            result = encrypt(text)
            
            # Output JSON with proper formatting
            output = json.dumps(result, indent=2)
            print(f"\n[✓] Encryption successful!")
            print(f"\n{output}")
            
            # Offer to save
            save_path = input("\nSave to file? (y/n): ").strip().lower()
            if save_path == 'y':
                filename = f"cipher_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2)
                print(f"[✓] Saved to: {filename}")
            
        except RandEncodeError as e:
            print(f"[!] Encryption error: {e}")
            sys.exit(1)
    else:
        # Command-line mode
        text = ' '.join(args)
        try:
            result = encrypt(text)
            print(json.dumps(result, indent=2))
        except RandEncodeError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


def decrypt_cli(filepath: Optional[str] = None) -> None:
    """
    Handle decryption from command line or interactive mode.
    
    Args:
        filepath: Path to JSON file, or None for interactive mode
        
    Example:
        decrypt_cli('cipher.json')
    """
    if filepath is None:
        # Interactive mode
        print("\n--- RandEncode Decryptor ---")
        
        cipher_input = input("\nEnter cipher hex or .json file path: ").strip()
        
        # Check if it's a file
        files = sorted(glob.glob(cipher_input))
        
        if files:
            success, msg = validate_json_file(files[0])
            print(f"Validation: {msg}")
            if not success:
                sys.exit(1)
            
            with open(files[0], 'r', encoding='utf-8') as f:
                meta = json.load(f)
        else:
            # Treat as hex cipher - need keys for decryption
            print("[!] Hex cipher requires saved keys to decrypt.")
            print("Please use a .json file that contains both cipher and keys.")
            return
        
        try:
            text = decrypt(meta['cipher'], meta['keys'])
            
            # Check time lock
            unlock_time = meta.get('unlock_time', 0)
            if not is_unlocked(unlock_time):
                remaining = int(unlock_time - datetime.now().timestamp())
                print(f"\n[!] Time-lock still active ({remaining // 3600}h {remaining % 3600 // 60}m remaining)")
                
            print(f"\n[✓] Decrypted text:")
            print(text)
            
        except KeyError as e:
            print(f"[!] Error: Missing field '{e}' in cipher file")
            sys.exit(1)
        except RandEncodeError as e:
            print(f"[!] Decryption error: {e}")
            sys.exit(1)
    else:
        # Command-line mode
        success, msg = validate_json_file(filepath)
        print(msg)
        if not success:
            sys.exit(1)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                meta = json.load(f)
            
            text = decrypt(meta['cipher'], meta['keys'])
            print(f"\nDecrypted: {text}")
            
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


def interactive_mode() -> None:
    """
    Main interactive loop.
    
    Provides menu-driven interface for encryption and decryption.
    """
    print("\n" + "="*60)
    print("       RandEncode v2.0 - Multi-Layer Time-Lock Encryption")
    print("       Improved: Better error handling, performance, safety")
    print("="*60)
    
    while True:
        print("\n--- Menu ---")
        print("1. Encrypt text")
        print("2. Decrypt cipher (from .json file)")
        print("3. Test encryption/decryption roundtrip")
        print("4. Show module info")
        print("5. Exit")
        
        try:
            choice = input("\nSelect [1-5]: ").strip()
            
            if choice == '1':
                encrypt_cli(None)
                
            elif choice == '2':
                decrypt_cli()
                
            elif choice == '3':
                test_text = input("Test text: ").strip() or "Hello RandEncode v2.0!"
                print(f"\n[Testing roundtrip with: {test_text}]")
                
                try:
                    encrypted = encrypt(test_text)
                    decrypted = decrypt(encrypted['cipher'], encrypted['keys'])
                    
                    if test_text == decrypted:
                        print(f"[✓] Roundtrip successful!")
                        print(f"    Original length: {len(test_text.encode('utf-8'))} bytes")
                        print(f"    Cipher: {encrypted['cipher'][:40]}..." if len(encrypted['cipher']) > 40 else f"    Cipher: {encrypted['cipher']}")
                    else:
                        print(f"[!] Roundtrip FAILED!")
                        print(f"    Expected: {repr(test_text)}")
                        print(f"    Got:      {repr(decrypted)}")
                except Exception as e:
                    print(f"[!] Test error: {e}")
                
            elif choice == '4':
                import platform
                print("\n--- Module Info ---")
                print(f"Version: 2.0.0")
                print(f"Python: {platform.python_version()}")
                print(f"OS: {platform.system()}")
                print(f"Dependencies: Python stdlib only (no external packages)")
                print("\n--- Algorithm ---")
                print(f"Modulus: 256 (2^8)")
                print(f"Layers: {NUM_LAYERS}")
                print(f"Default time-lock: {DEFAULT_TIMELOCK // 3600}h")
                
            elif choice == '5':
                print("\nGoodbye!")
                break
            else:
                print("[!] Invalid option. Please enter 1-5.")
                
        except KeyboardInterrupt:
            print("\n\n[!] Interrupted by user")
            sys.exit(0)
        except EOFError:
            print("\n\n[!] End of input")
            sys.exit(0)