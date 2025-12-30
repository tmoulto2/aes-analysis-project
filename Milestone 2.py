"""
Milestone #2 Solution
Author: Tyfanna Moulton

Description:
------------
This program decrypts an encrypted message using a provided RSA key pair. 
The dataset consists of:
    - A private RSA key file (`private_key.pem`)
    - A public RSA key file (`public_key.pem`)
    - An encrypted message file (`emessage.etxt`)

Steps:
1. Store all three files in the "milestone_2_data" folder.
2. Load the private RSA key from the PEM file.
3. Read the encrypted message from `emessage.etxt`.
4. Decrypt the message using RSA-OAEP with SHA-1 padding.
5. Print the plain-text contents of the decrypted message.

Assumptions:
------------
- The message was encrypted directly with RSA (2048-bit key length).
- Standard OAEP padding (SHA-1) was used for encryption.
- No password protection is applied to the private key.

External References:
--------------------
- Python cryptography library: https://cryptography.io/en/latest/
- Python os documentation: https://docs.python.org/3/library/os.html
- RSA OAEP documentation (RFC 8017): https://www.rfc-editor.org/rfc/rfc8017
"""

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

# Folder containing your files
data_folder = "milestone_2_dataset"

# Build full paths to each file
private_key_path = os.path.join(data_folder, "private_key.pem")
encrypted_path = os.path.join(data_folder, "emessage.etxt")

# --- Load your private key ---
with open(private_key_path, "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None)

# --- Read the encrypted message ---
with open(encrypted_path, "rb") as f:
    encrypted_data = f.read()

# --- Decrypt using RSA-OAEP (SHA1) ---
plaintext = private_key.decrypt(
    encrypted_data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
    )
)

print("Decrypted message:", plaintext.decode())
