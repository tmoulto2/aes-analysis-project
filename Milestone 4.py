"""

Milestone #4 Solution
Author: Tyfanna Moulton

Description:
------------
This program performs full end-to-end decryption of a layered cryptographic dataset
using RSA and AES. The dataset contains hundreds of RSA-encrypted AES session keys
and tens of thousands of AES-encrypted messages. Only one RSA private key correctly
decrypts the valid AES key, and only one AES-encrypted message contains the secret
plaintext.

The program automates the decryption process by:
  1. Iterating through RSA private keys to decrypt AES session keys.
  2. Validating the correct AES key using an MD5 hash comparison.
  3. Using the recovered AES-256 key to decrypt all encrypted messages.
  4. Identifying the correct plaintext message by matching its MD5 hash.

AES decryption is performed using AES-256 in CBC mode with a 16-byte zero
initialization vector (IV), consistent with the encryption parameters used
in the dataset and earlier milestones.

Once the correct message is identified, the plaintext is printed to the console
and cryptographic integrity is verified using MD5 hashing.

Dataset Components:
-------------------
- RSA private keys: Used to decrypt AES session keys
- Encrypted AES session keys (.eaes files)
- AES-encrypted messages (.emsg files)
- MD5 hash files used for validation:
    - plain_aes_hash.md5
    - plain_master_message_hash.md5

Tools & Environment:
--------------------
- Python 3.11
- PyCryptodome library for RSA and AES operations
- Standard Python libraries (hashlib, glob, os, re)
- Visual Studio Code development environment

Methodology Summary:
--------------------
- RSA decryption is attempted against all AES session keys.
- Each decrypted AES key is validated using MD5 hashing.
- The correct AES key is used to decrypt all encrypted messages.
- The decrypted message matching the known MD5 hash is identified
  as the secret plaintext.

This milestone demonstrates structured cryptographic analysis, automation,
validation techniques, and responsible handling of encryption without
attempting to break or weaken cryptographic algorithms.

External References:
--------------------
- PyCryptodome documentation: https://pycryptodome.readthedocs.io/
- NIST FIPS 197 – Advanced Encryption Standard (AES):
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
- RFC 1321 – The MD5 Message-Digest Algorithm:
  https://www.rfc-editor.org/rfc/rfc1321
- Python 3.11 documentation: https://docs.python.org/3/

"""

import os
import re
import glob
from hashlib import md5

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES



DATASET_DIR = "dataset"   


def read_md5(path):
    with open(path, "rb") as f:
        return f.read().strip().decode("ascii")


def load_file(path):
    with open(path, "rb") as f:
        return f.read()


def find_correct_aes_key():
    """
    Try every (private_keyX, session_keyY.eaes) combination until
    md5(plaintext_aes_key) matches the provided plain_aes_hash.md5.
    """
    hashes_dir = os.path.join(DATASET_DIR, "hashes")
    target_aes_md5 = read_md5(os.path.join(hashes_dir, "plain_aes_hash.md5"))

    rsa_dir = os.path.join(DATASET_DIR, "rsa")
    aes_dir = os.path.join(DATASET_DIR, "aes")

    priv_files = sorted(
        glob.glob(os.path.join(rsa_dir, "private_key*.pem")),
        key=lambda s: int(re.search(r"(\d+)", s).group(1))
    )
    aes_files = sorted(
        glob.glob(os.path.join(aes_dir, "session_key*.eaes")),
        key=lambda s: int(re.search(r"(\d+)", s).group(1))
    )

    print(f"[+] Target AES key MD5: {target_aes_md5}")
    print(f"[+] Found {len(priv_files)} RSA private keys")
    print(f"[+] Found {len(aes_files)} encrypted AES keys\n")

    
    for priv_path in priv_files:
        priv_pem = load_file(priv_path)
        rsa_key = RSA.import_key(priv_pem)
        rsa_cipher = PKCS1_OAEP.new(rsa_key)

        for aes_path in aes_files:
            aes_ct = load_file(aes_path)
            try:
                aes_pt = rsa_cipher.decrypt(aes_ct)
            except Exception:
                # wrong key / wrong padding, skip
                continue

            h = md5(aes_pt).hexdigest()
            if h == target_aes_md5:
                print("[+] Found matching AES key!")
                print(f"    RSA private key file: {priv_path}")
                print(f"    Encrypted AES file : {aes_path}")
                print(f"    AES key (hex)      : {aes_pt.hex()}")
                print(f"    AES key length     : {len(aes_pt)} bytes\n")
                return aes_pt, aes_path, priv_path

    raise RuntimeError("No AES key matched the provided AES MD5 hash!")


def decrypt_message_with_key(aes_key, ciphertext):
    """
    Decrypt AES ciphertext using AES-256-CBC with a zero IV.
    This matches Milestone 3 and the instructor's dataset.
    """
    iv = b"\x00" * 16
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext  # no padding used


def find_secret_message(aes_key):
    """
    Use the discovered AES key to decrypt all messages and compare
    the plaintext MD5 to plain_master_message_hash.md5.
    """
    hashes_dir = os.path.join(DATASET_DIR, "hashes")
    target_msg_md5 = read_md5(os.path.join(hashes_dir, "plain_master_message_hash.md5"))
    print(f"[+] Target master message MD5: {target_msg_md5}\n")

    msg_dir = os.path.join(DATASET_DIR, "messages")
    msg_files = sorted(
        glob.glob(os.path.join(msg_dir, "message*.emsg")),
        key=lambda s: int(re.search(r"(\d+)", s).group(1))
    )

    print(f"[+] Found {len(msg_files)} encrypted messages\n")

    for i, msg_path in enumerate(msg_files, start=1):
        ct = load_file(msg_path)
        try:
            pt = decrypt_message_with_key(aes_key, ct)
        except Exception:
            continue

        h = md5(pt).hexdigest()
        if h == target_msg_md5:
            print("[+] Found the secret message!")
            print(f"    Message file : {msg_path}")
            print(f"    MD5(plaintext): {h}")
            try:
                decoded = pt.decode("utf-8", errors="replace")
            except Exception:
                decoded = repr(pt)
            print("\n===== SECRET MESSAGE (raw) =====")
            print(decoded)
            print("================================\n")
            return pt, msg_path


def main():
    print("=== Step 1: Find correct AES key via RSA and MD5 ===")
    aes_key, aes_file, priv_file = find_correct_aes_key()

    print("=== Step 2: Use AES key to find secret message ===")
    secret_plaintext, secret_msg_file = find_secret_message(aes_key)

    print("=== Summary ===")
    print(f"Correct RSA private key file: {priv_file}")
    print(f"Correct AES session file    : {aes_file}")
    print(f"Secret message file         : {secret_msg_file}")

    # Show hash confirmation
    print("\n=== Verification Hashes ===")
    print(f"MD5(AES key)       : {md5(aes_key).hexdigest()}")
    print(f"MD5(secret message): {md5(secret_plaintext).hexdigest()}")


if __name__ == "__main__":
    main()
