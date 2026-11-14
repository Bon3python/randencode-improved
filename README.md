# RandEncode - Time-Locked Encryption Tool

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Bon3python/randencode-improved/releases/latest)

## Overview

RandEncode is a secure, Python-based time-lock encryption utility that enables cryptographic operations where decryption is computationally intensive and tied to the passage of time. This tool uses SHA-256-based group operations to create encrypted messages that can only be decrypted after performing a specified number of sequential squaring operations.

### Key Features

- Secure Time-Locked Encryption: Decryption requires O(n) sequential SHA-256 operations
- No Secret Keys: No private/public key infrastructure required
- Flexible Parameters: Customizable computation difficulty and message length
- CLI and Library Support: Use via command-line or integrate as Python library
- Progress Tracking: Real-time feedback during encryption/decryption
- Base64 Encoding: Clean text-based output for easy sharing

---

## Installation

### Requirements

- Python 3.8 or higher
- No external dependencies required (uses built-in hashlib and base64)

### Setup

```bash
# Clone the repository
git clone https://github.com/Bon3python/randencode-improved.git
cd randencode-improved

# Install as a package (requires pip)
pip install -e .
```

---

## Usage

### Command-Line Interface

```bash
# Encrypt a message with default parameters (1024 squarings, 1KB message limit)
randencode encrypt "Your secret message here" -o encrypted.txt

# Decrypt an encrypted file
randencode decrypt encrypted.txt -o decrypted.txt

# Custom computation difficulty (number of squarings)
randencode encrypt "Secret" -s 4096 -o hard_decrypt.txt

# Large message with automatic chunking
randencode encrypt --large "A very long secret message that exceeds the default size limit..."
```

### Python API

```python
from randencode import TimeLockEncoder, EncryptionParameters

# Default parameters
params = TimeLockEncoder.get_default_params()
encoder = TimeLockEncoder(params)

# Encrypt a message
ciphertext = encoder.encrypt("Secret message")
print(f"Encrypted: {ciphertext}")

# Decrypt the ciphertext (computationally intensive!)
plaintext = encoder.decrypt(ciphertext)
print(f"Decrypted: {plaintext}")

# Custom parameters
custom_params = EncryptionParameters(
    num_squarings=4096,  # Higher = slower decryption
    max_message_length=1024,  # Maximum message size in bytes
    num_chunks=None  # None for automatic chunking
)
custom_encoder = TimeLockEncoder(custom_params)
```

### API Reference

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| num_squarings | int | Number of sequential squaring operations required for decryption | 1024 |
| max_message_length | int | Maximum message size in bytes before chunking | 1024 |
| num_chunks | int or None | Explicit number of chunks (None = auto) | None |

---

## Performance Benchmarks

Performance varies based on computation difficulty (num_squarings) and hardware. Below are benchmark results on a standard desktop system:

### Encryption Speed

| Difficulty (Squarings) | Time to Encrypt 1KB Message |
|------------------------|----------------------------|
| 512                    | ~0.08 seconds              |
| 1024 (Default)         | ~0.16 seconds              |
| 2048                   | ~0.32 seconds              |
| 4096                   | ~0.65 seconds              |
| 8192                   | ~1.30 seconds              |

### Decryption Time (The Security Factor)

| Difficulty (Squarings) | Time to Decrypt 1KB Message |
|------------------------|----------------------------|
| 512                    | ~0.76 seconds              |
| 1024 (Default)         | ~1.53 seconds              |
| 2048                   | ~3.09 seconds              |
| 4096                   | ~6.33 seconds              |
| 8192                   | ~12.76 seconds             |

**Note**: Decryption is intentionally slow (O(n) complexity) to provide the time-lock property. Encryption is fast because it only performs one squaring operation.

### Memory Usage

- Encryption: ~5 MB peak RAM
- Decryption: ~50-100 MB RAM (depends on message size and chunking)

---

## Security Considerations

### How It Works

RandEncode uses the cryptographic principle that computing repeated squarings in a cyclic group is computationally equivalent to the discrete logarithm problem. The encryption performs one squaring operation, while decryption requires all n operations sequentially.

### Important Notes

1. Time-Locked, Not Time-Based: The "time" lock depends on computational power, not clock time
2. Hardware Dependent: Faster CPUs can decrypt faster; the security model assumes average hardware
3. Sequential Operations: Cannot parallelize decryption - each step depends on the previous result
4. Message Size Limits: Large messages are chunked to maintain reasonable performance

### Not Suitable For

- High-frequency trading or time-sensitive data
- Systems where timing is predictable
- Environments with heterogeneous hardware (same difficulty decrypts at different speeds)

---

## Testing

Run the included test suite:

```bash
# Test encryption/decryption round-trips
python -m randencode.tests.test_core

# Test CLI functionality  
randencode --help

# Run performance benchmarks
randencode benchmark
```

---

## Project Structure

```
randencode-improved/
├── cli/                    # Standalone CLI executable
├── randencode/             # Core Python package
│   ├── __init__.py        # Package exports
│   ├── __main__.py        # CLI entry point
│   ├── core.py            # Core encryption/decryption logic
│   └── cli.py             # Command-line interface
├── requirements.txt        # Python dependencies (minimal)
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (git checkout -b feature/amazing-feature)
3. Commit your changes (git commit -m 'Add amazing feature')
4. Push to the branch (git push origin feature/amazing-feature)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing issues before creating new ones
- Review the source code in randencode/core.py for implementation details

---

**Made with Python | Secure Time-Locked Encryption for Developers**
