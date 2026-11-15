# RandEncode

RandEncode is an experimental Python encryption tool exploring layered byte 
transformation with built-in key management and time-locked decryption.

The goal of this project is to build a functional, privacy-first encryption 
tool from scratch — no external cryptographic libraries, no servers, 
no third party trust.

## Features
- Multi-layer encoding using randomized modular arithmetic
- Cryptographically secure key generation via Python's `secrets` module
- Automatic key file management — keys are never handled manually
- Time-lock decryption — encrypted data cannot be decrypted until a set time
- Secure key erasure — key file is overwritten with random bytes 3 times 
  before deletion after successful decryption

## How It Works
1. Choose encrypt or decrypt from the menu
2. On encryption, enter your message and a timelock duration in seconds
3. The program saves the cipher and keys to a local key file automatically
4. On decryption, enter the cipher hex — the program checks the timelock 
   and decrypts using the saved keys without any manual key input

## Important Notes
- This project is not yet cryptographically secure for commercial or 
  sensitive use — it is a learning project and work in progress
- All keys and ciphers are stored locally — no servers or external 
  libraries are involved by design
- Currently single-file only — one key file per encryption session

## Requirements
Python 3.8 or higher. No external libraries required.
