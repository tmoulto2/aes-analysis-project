"""
Milestone #3 Solution
Author: Tyfanna Moulton

Description:
------------
This program decrypts an AES-encrypted message using a provided AES key file.
The dataset includes:
  - AES_key_.aes: contains the 32-byte AES key (for AES-256).
  - emessage.etxt: contains the encrypted message.

The program reads the key and ciphertext, sets an initialization vector (IV)
consisting of all zero bytes, and performs AES decryption in CBC mode.
After decryption, the plaintext is printed to the console.

External References:
--------------------
- Python Cryptodome library: https://pycryptodome.readthedocs.io/
- AES encryption standards: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
"""

from Crypto.Cipher import AES

# Define file paths
key_path = "milestone_3_dataset/AES_key_.aes"
encrypted_path = "milestone_3_dataset/emessage.etxt"

# Read AES key (expected 32 bytes for AES-256)
with open(key_path, "rb") as key_file:
    key = key_file.read().strip()

# Read ciphertext from file
with open(encrypted_path, "rb") as enc_file:
    ciphertext = enc_file.read()

# AES block size is 16 bytes
iv = b"\x00" * 16  # Blank IV of 16 null bytes

# Initialize AES cipher for CBC mode decryption
cipher = AES.new(key, AES.MODE_CBC, iv)

# Perform decryption
plaintext = cipher.decrypt(ciphertext)

# Decode plaintext and clean up padding/nulls
try:
    message = plaintext.decode("utf-8").rstrip("\x00").strip()
except UnicodeDecodeError:
    message = plaintext.decode("latin-1").rstrip("\x00").strip()

# Display the decrypted message
print("Decrypted message:", message)
