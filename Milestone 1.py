"""
Milestone #1 Solution
Author: Tyfanna Moulton

Description:
------------
This program identifies which plain-text file in a dataset matches a given MD5 hash.
The dataset consists of a collection of text files and a separate file (`message_hash.md5`)
that contains the target MD5 hash value. 

Steps:
1. Extract the dataset ZIP file into a folder.
2. Read the target MD5 hash from `message_hash.md5`.
3. Compute the MD5 hash of each plain-text file.
4. Compare hashes until a match is found.
5. Print the matching file name.

External References:
--------------------
- Python hashlib documentation: https://docs.python.org/3/library/hashlib.html
- Python zipfile documentation: https://docs.python.org/3/library/zipfile.html
- Python os documentation: https://docs.python.org/3/library/os.html
"""

import zipfile   # For extracting the dataset .zip file
import os        # For file and folder path operations
import hashlib   # For MD5 hashing

# -----------------------------
# Step 1: Define file locations
# -----------------------------

# Path to the dataset .zip file (update with your path if needed)
zip_path = r"C:\Users\tyfan\OneDrive\Desktop\KSU Fall 2025\Milestone_1_dataset.zip"

# Directory where the dataset will be extracted
extract_dir = r"C:\Users\tyfan\OneDrive\Desktop\KSU Fall 2025\milestone_dataset"

# -----------------------------
# Step 2: Extract the dataset
# -----------------------------
with zipfile.ZipFile(zip_path, 'r') as zip_ref:
    zip_ref.extractall(extract_dir)

# After extraction, locate the dataset folder
dataset_path = os.path.join(extract_dir, "Milestone_1_dataset")

# -----------------------------
# Step 3: Read the target MD5 hash
# -----------------------------
hash_file_path = os.path.join(dataset_path, "message_hash.md5")
with open(hash_file_path, "r") as f:
    target_hash = f.read().strip()  # Remove whitespace/newlines

# -----------------------------
# Step 4: Function to compute MD5 of a file
# -----------------------------
def compute_md5(file_path):
    """
    Compute the MD5 hash of a file.
    Reads the file in chunks to handle large files efficiently.
    """
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:  # Open in binary mode
        for chunk in iter(lambda: f.read(4096), b""):  # Read in 4KB chunks
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# -----------------------------
# Step 5: Search for matching file
# -----------------------------
plain_files_dir = os.path.join(dataset_path, "plain_files")
matching_file = None

# Walk through all files in the "plain_files" directory
for root, dirs, files in os.walk(plain_files_dir):
    for file in files:
        file_path = os.path.join(root, file)
        file_hash = compute_md5(file_path)

        # Compare computed hash with target hash
        if file_hash == target_hash:
            matching_file = file
            break
    if matching_file:
        break

# -----------------------------
# Step 6: Output result
# -----------------------------
if matching_file:
    print("Matching file found:", matching_file)
else:
    print("No matching file found.")
