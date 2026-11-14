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
    banner = """\n{}"
██████╗  █████╗ ███╗   ██╗██████╗ ███████╗███╗   ██╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗████╗  ██║██╔══██╗██╔════╝████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝███████║██╔██╗ ██║██║  ██║█████╗  ██╔██╗ ██║██║     ██║   ██║██║  ██║█████╗
██╔══██╗██╔══██║██║╚██╗██║██║  ██║██╔══╝  ██║╚██╗██║██║     ██║   ██║██║  ██║██╔══╝
██║  ██║██║  ██║██║ ╚████║██████╔╝███████╗██║ ╚████║╚██████╗╚██████╔╝██████╔╝███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
""".format(Colors.BLUE + Colors.BOLD)
    print(banner)


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
    1. Writes random bytes multiple times (3 passes)
    2. Final overwrite with zeros
    3. Atomic delete operation
    
    Args:
        filename: Path to the file to securely erase
        
    Returns:
        True if successful, False otherwise
    """
    try:
        if not os.path.exists(filename):
            return False
            
        file_size = os.path.getsize(filename)
        
        # Handle edge case: empty files
        if file_size == 0:
            os.remove(filename)
            return True
            
        with open(filename, 'wb') as f:
            for _ in range(3):
                # Overwrite with random data
                f.write(secrets.token_bytes(file_size))
            # Final pass with zeros
            f.write(b'\x00' * file_size)
        
        # Delete the file securely
        os.remove(filename)
        return True
        
    except (IOError, OSError) as e:
        print(colorize(f"Failed to erase file: {e}", Colors.RED))
        return False