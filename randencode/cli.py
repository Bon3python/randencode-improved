"""
Command-line interface for RandEncode.

Provides user-friendly encryption/decryption with proper error handling.
"""

import sys
import json
import os
import time
import secrets
from typing import Optional, Tuple

from randencode.core import RandEncodeEngine, EncryptionError


# ANSI color codes for better terminal output
class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def colorize(text: str, color: str) -> str:
    """Apply color to text."""
    return f"{color}{text}{Colors.RESET}"


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Print the RandEncode banner."""
    banner = "\n{}".format(Colors.BLUE + Colors.BOLD)
    print(banner)
    print()


def prompt_user(prompt: str, default: Optional[str] = None, validate_func=None) -> str:
    """
    Get user input with optional validation.
    
    Args:
        prompt: The prompt text to display
        default: Default value if empty (None for required)
        validate_func: Optional function that returns True if input is valid
        
    Returns:
        Validated user input
    """
    while True:
        if default:
            result = input(f"{prompt} [{default}]: ").strip()
            if not result:
                result = default
        else:
            result = input(f"{prompt}: ").strip()
        
        if validate_func and not validate_func(result):
            print(colorize("Invalid input. Please try again.", Colors.RED))
            continue
            
        return result


def get_positive_integer(prompt: str) -> int:
    """Get a positive integer from user input."""
    while True:
        try:
            value = prompt_user(prompt, validate_func=lambda x: x.isdigit() and int(x) > 0)
            return int(value)
        except ValueError:
            continue


def get_non_negative_integer(prompt: str) -> int:
    """Get a non-negative integer from user input."""
    while True:
        try:
            value = prompt_user(prompt, validate_func=lambda x: x.isdigit() and int(x) >= 0)
            return int(value)
        except ValueError:
            continue


def save_keys_to_file(data: dict, filename: str = "keys.json") -> bool:
    """Save encryption keys to a JSON file."""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except (IOError, OSError, json.JSONDecodeError) as e:
        print(colorize(f"Failed to save keys: {e}", Colors.RED))
        return False


def secure_erase_file(filename: str) -> bool:
    """
    Securely erase a file by overwriting with random data multiple times before deletion.
    
    This implementation follows security best practices for sensitive file erasure:
    1. Writes random data to the file multiple times
    2. Performs one final write of zeros
    3. Attempts to delete the file
    
    Returns True if successful, False otherwise.
    """
    if not os.path.exists(filename):
        return True
    
    try:
        # Overwrite with random data 3 times
        for _ in range(3):
            with open(filename, 'wb') as f:
                f.write(secrets.token_bytes(os.path.getsize(filename)))
        
        # Final overwrite with zeros
        with open(filename, 'wb') as f:
            f.write(b'\x00' * os.path.getsize(filename))
        
        # Delete the file
        os.remove(filename)
        return True
    except (IOError, OSError) as e:
        print(colorize(f"Failed to securely erase file: {e}", Colors.RED))
        return False


def encrypt_message(engine: RandEncodeEngine, plaintext: str, delay_seconds: int) -> Tuple[Optional[str], bool]:
    """
    Encrypt a message and save keys to file.
    
    Args:
        engine: The RandEncodeEngine instance
        plaintext: Text to encrypt
        delay_seconds: Time in seconds before decryption is allowed
        
    Returns:
        Tuple of (hex cipher string, success flag)
    """
    try:
        result = engine.encrypt(plaintext, delay_seconds)
        
        # Save keys to file for later decryption
        if save_keys_to_file({
            'keys': result['keys'],
            'unlock_time': result['unlock_time']
        }):
            print(colorize("Keys saved successfully!", Colors.GREEN))
        
        # Return hex string of cipher bytes for CLI display
        cipher_bytes = bytes.fromhex(result['cipher'])
        return result['cipher'].replace(' ', ''), True
        
    except EncryptionError as e:
        print(colorize(f"Encryption error: {e}", Colors.RED))
        return None, False


def decrypt_message(engine: RandEncodeEngine, cipher_hex: str, save_filename: Optional[str] = None) -> Tuple[Optional[str], bool]:
    """
    Decrypt a message using saved keys.
    
    Args:
        engine: The RandEncodeEngine instance
        cipher_hex: Hex string of encrypted data
        save_filename: Optional filename to save keys from (for loading)
        
    Returns:
        Tuple of (decrypted text, success flag)
    """
    # Load keys if saving to file
    if save_filename and os.path.exists(save_filename):
        try:
            with open(save_filename, 'r') as f:
                data = json.load(f)
            engine.key_manager.keys = data.get('keys', [])
            engine.key_manager.unlock_time = data.get('unlock_time', 0)
        except (json.JSONDecodeError, IOError):
            print(colorize("Failed to load keys from file", Colors.RED))
            return None, False
    
    if not engine.can_decrypt():
        unlock_date = time.strftime("%Y-%m-%d %H:%M:%S", 
                                     time.localtime(engine.key_manager.unlock_time))
        remaining = int(engine.key_manager.unlock_time - time.time())
        print(colorize(
            f"Decryption locked until {unlock_date} ({remaining} seconds remaining)",
            Colors.YELLOW
        ))
        return None, False
    
    try:
        encrypted_bytes = bytes.fromhex(cipher_hex.replace(' ', ''))
    except ValueError as e:
        print(colorize(f"Invalid hex string: {e}", Colors.RED))
        return None, False
    
    try:
        decrypted_text = engine.decrypt(list(encrypted_bytes))
        
        # Erase keys if we're saving to file
        keys_erased = secure_erase_file(save_filename) if save_filename else True
        return decrypted_text, keys_erased
        
    except EncryptionError as e:
        print(colorize(f"Decryption error: {e}", Colors.RED))
        return None, False


def run_interactive():
    """Run the interactive CLI menu."""
    print_banner()
    
    engine = RandEncodeEngine()
    
    while True:
        print()
        print("1 - Encrypt message")
        print("2 - Decrypt message")
        print("3 - Exit")
        print()
        
        choice = input("Choose an option: ").strip()
        
        if choice == '1':
            clear_screen()
            print_banner()
            
            plaintext = prompt_user(
                "Enter text to encrypt", 
                validate_func=lambda x: len(x) > 0,
                default=""
            )
            
            delay_seconds = get_non_negative_integer("Enter timelock duration in seconds")
            
            print()
            print(f"Encrypting: {colorize(plaintext[:50], Colors.CYAN)}...")
            
            cipher, keys = encrypt_message(engine, plaintext, delay_seconds)
            
            if cipher:
                print()
                print(colorize("Encryption successful!", Colors.GREEN))
                print(f"   Encrypted hex (first 100 chars): {cipher[:100]}{'...' if len(cipher) > 100 else ''}")
                print(f"   Total keys used: {len(engine.key_manager.keys)}")
                print(f"   Keys saved to: keys.json")
                print()
                
        elif choice == '2':
            clear_screen()
            print_banner()
            
            # Load existing keys if file exists
            if os.path.exists("keys.json"):
                with open("keys.json", 'r') as f:
                    data = json.load(f)
                engine.key_manager.keys = data.get('keys', [])
                engine.key_manager.unlock_time = data.get('unlock_time', 0)
            
            cipher_hex = prompt_user(
                "Enter encrypted hex string",
                validate_func=lambda x: all(c in '0123456789abcdef' for c in x.lower() if c),
                default=""
            )
            
            print()
            decrypted_text, keys_erased = decrypt_message(engine, cipher_hex, "keys.json")
            
            if decrypted_text:
                print(colorize("Decryption successful!", Colors.GREEN))
                print(f"   Decrypted text: {decrypted_text}")
                
        elif choice == '3':
            print(colorize("Goodbye!", Colors.BLUE))
            sys.exit(0)
            
        else:
            print(colorize("Invalid choice. Please try again.", Colors.RED))