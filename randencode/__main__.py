"""
RandEncode - Multi-layer modular arithmetic encryption with time-lock.

Usage:
    python -m randencode          # Interactive mode
    python -m randencode encrypt "text"     # Encrypt to stdout (JSON)
    python -m randencode decrypt cipher.json  # Decrypt from file

Examples:
    # Encryption
    $ python -m randencode encrypt "Hello World"
    {
      "cipher": "45 67 89 ab cd ...",
      "keys": [123, 456, 789, 234],
      ...
    }
    
    # Decryption
    $ python -m randencode decrypt cipher.json
    Decrypted: Hello World!

API Usage:
    from randencode import encrypt, decrypt, mod_inverse
    
    # Encrypt
    data = encrypt("secret message")
    
    # Decrypt  
    text = decrypt(data['cipher'], data['keys'])
"""
