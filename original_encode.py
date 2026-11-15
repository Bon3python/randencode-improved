import json
import os
import secrets
import sys
import time

banner = r"""
██████╗  █████╗ ███╗   ██╗██████╗ ███████╗███╗   ██╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗████╗  ██║██╔══██╗██╔════╝████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝
██████╔╝███████║██╔██╗ ██║██║  ██║█████╗  ██╔██╗ ██║██║     ██║   ██║██║  ██║█████╗
██╔══██╗██╔══██║██║╚██╗██║██║  ██║██╔══╝  ██║╚██╗██║██║     ██║   ██║██║  ██║██╔══╝
██║  ██║██║  ██║██║ ╚████║██████╔╝███████╗██║ ╚████║╚██████╗╚██████╔╝██████╔╝███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
"""

print(banner)


def secure_erase(filename):
    if os.path.exists(filename):
        size = os.path.getsize(filename)
        with open(filename, "wb") as f:
            for _ in range(3):
                f.write(os.urandom(size))
        os.remove(filename)
        print("securely erased")
    else:
        print("file not found")


def encrypt():
    text_to_encrypt = input("input text to encrypt: ")
    lock_time = int(input("input timelock value: "))

    print(f"{text_to_encrypt}")

    text_bytes = list(text_to_encrypt.encode())

    print(
        f"original message bytes were {text_bytes}, length of the message was {len(text_bytes)} characters"
    )
    counter = 1

    results = []

    def randencode(text_bytes):
        key = secrets.choice(range(1, 256, 2))

        supercode = [(b * key) % 256 for b in text_bytes]

        return supercode, key

    results = []
    keylist = []
    data = []

    for i in range(3):
        text_bytes, key = randencode(text_bytes)
        keylist.append(key)
        results.append({"layer": counter, "key": key, "cipher": text_bytes.copy()})

        counter += 1
        cipher_hex = " ".join(f"{b:02x}" for b in text_bytes)

    data = {
        "keys": keylist,
        "unlock_time": time.time() + lock_time,
        "cipher": cipher_hex,
    }

    with open("keys.json", "w") as f:
        json.dump(data, f)

    print(f"final encoded hex: {cipher_hex}")
    print(f"final key: {key}")
    print(f"results: {results}")

    with open("keys.json", "r") as f:
        data = json.load(f)
    print(f"keys: {data}")

    if time.time() < data["unlock_time"]:
        print("still locked")
    else:
        print(data["keys"])

    filename = "keys.json"

    # end of encrypt() function


def decrypt():

    def mod_inverse(a, mod=256):
        for x in range(mod):
            if (a * x) % mod == 1:
                return x
        raise ValueError(f"no inverse for {a}")

    def decrypt_layer(data, key):
        inv = mod_inverse(key)
        return [(b * inv) % 256 for b in data]

    print("=== INTERACTIVE DECODER ===")
    print("enter ciphertext bytes separated by spaces")
    print("example: 145 242 83\n")

    cipher_hex = input("Ciphertext hex: ")
    cipher = list(bytes.fromhex(cipher_hex))

    if not os.path.exists("keys.json"):
        print(
            "no key file found — file may have already been decrypted or never existed"
        )
        return

    with open("keys.json", "r") as f:
        data = json.load(f)

    if cipher_hex == data["cipher"]:
        print("ciphertext found")
    else:
        print("no matching cipher found")
        return

    if time.time() < data["unlock_time"]:
        print("still locked")
        return
    else:
        print("unlock time reached")

    for key in reversed(data["keys"]):
        cipher = decrypt_layer(cipher, key)

    print("\nFINAL RESULT:")
    print("bytes:", cipher)

    try:
        print("text:", bytes(cipher).decode())
    except:
        print("text: <decode failed>")

    secure_erase("keys.json")

    # end of decrypt() function


# menu
while True:
    print("1 - encrypt")
    print("2 - decrypt")
    print("3 - exit")
    choice = input("choose: ")

    if choice == "1":
        encrypt()
    elif choice == "2":
        decrypt()
    elif choice == "3":
        print("goodbye")
        sys.exit()
    else:
        print("invalid choice")
