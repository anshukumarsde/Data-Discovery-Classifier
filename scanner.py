"""
Data Discovery Classifier - Directory Scanner

Walks through a directory, reads text-like files, and scans them
for sensitive data such as email addresses, SSNs, credit card
numbers, and phone numbers.

Credit card numbers are validated using the Luhn checksum.
Files are classified as INTERNAL, CONFIDENTIAL, or RESTRICTED.
CONFIDENTIAL files are encrypted using Fernet encryption.
Previously encrypted text files are scanned in memory so their report rows remain.

Usage:
    py scanner.py <directory>

Decrypt a file:
    py scanner.py --decrypt <encrypted_file>
"""

import os
import sys
import re
import csv
from cryptography.fernet import Fernet

# Sensitive-data patterns
EMAIL_PATTERN = r"\S+@\S+\.\S+"
SSN_PATTERN = r"\d{3}-\d{2}-\d{4}"
CARD_PATTERN = r"\d{16}"
PHONE_PATTERN = r"\d{3}-\d{3}-\d{4}"

# File extensions that will be treated as text files
TEXT_EXTENSIONS = [".txt", ".csv", ".json", ".xml", ".log"]

# File used to store the encryption key
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE_DIR, "secret.key")

# Validates a card number using the Luhn checksum
def is_valid_card(card_number):
    digits = []
    for digit in card_number:
        digits.append(int(digit))
    # start from the second digit from the right
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    total = sum(digits)
    return total % 10 == 0

# Creates an encryption key if one does not already exist
def get_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

# Encrypts the file and removes the plaintext version
def encrypt_file(file_path):
    key = get_key()
    cipher = Fernet(key)
    # Read the original file
    with open(file_path, "rb") as file:
        data = file.read()
    # Encrypt the contents
    encrypted_data = cipher.encrypt(data)
    encrypted_file_path = file_path + ".encrypted"
    # Write the encrypted contents
    with open(encrypted_file_path, "wb") as file:
        file.write(encrypted_data)
    # Remove the plaintext file after encryption succeeds
    os.remove(file_path)
    print("File encrypted: ", file_path)

# Decrypts an encrypted file
def decrypt_file(file_path):
    if not os.path.exists(KEY_FILE):
        print("Error: secret.key was not found.")
        return
    with open(KEY_FILE, "rb") as key_file:
        key = key_file.read()
    cipher = Fernet(key)
    # Read the encrypted file
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    # Decrypt the contents
    decrypted_data = cipher.decrypt(encrypted_data)
    # Remove .encrypted from the file name
    original_file_path = file_path.removesuffix(".encrypted")
    # Restore the original file
    with open(original_file_path, "wb") as file:
        file.write(decrypted_data)
    # Remove the encrypted version after decryption succeeds
    os.remove(file_path)
    print("File decrypted: ", original_file_path)

# Make sure a command-line argument was provided
if len(sys.argv) < 2:
    print("Usage: py scanner.py <directory>")
    sys.exit()

# Decrypt mode
if sys.argv[1] == "--decrypt":
    if len(sys.argv) < 3:
        print("Usage: py scanner.py --decrypt <encrypted_file>")
        sys.exit()
    decrypt_file(sys.argv[2])
    sys.exit()

# Directory to scan
directory = sys.argv[1]

# Create a CSV report
with open("report.csv", "w", newline="", encoding="utf-8") as report:
    writer = csv.writer(report)
    # Write the report header
    writer.writerow([
        "Path",
        "Classification",
        "Email Count",
        "SSN Count",
        "Credit Card Count",
        "Phone Number Count"
    ])
    # Walk through the directory and all subdirectories
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            is_encrypted = file.endswith(".encrypted")
            original_path = file_path.removesuffix(".encrypted") if is_encrypted else file_path
            # Only scan text-like files
            if os.path.splitext(original_path)[1].lower() in TEXT_EXTENSIONS:
                # If both versions exist, scan the current plaintext only.
                if is_encrypted and os.path.basename(original_path) in files:
                    continue
                if is_encrypted:
                    # Read the existing key; never generate a replacement for decryption.
                    with open(KEY_FILE, "rb") as key_file:
                        cipher = Fernet(key_file.read())
                    with open(file_path, "rb") as f:
                        content = cipher.decrypt(f.read()).decode("utf-8")
                else:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                emails = re.findall(EMAIL_PATTERN, content)
                ssns = re.findall(SSN_PATTERN, content)
                cards = re.findall(CARD_PATTERN, content)
                phone_numbers = re.findall(PHONE_PATTERN, content)

                # Only keep card numbers that pass the Luhn checksum
                valid_cards = []
                for card in cards:
                    if is_valid_card(card):
                        valid_cards.append(card)

                # Assign the file classification
                if len(valid_cards) > 0 or len(ssns) > 0:
                    classification = "RESTRICTED"
                elif len(emails) > 0 or len(phone_numbers) > 0:
                    classification = "CONFIDENTIAL"
                else:
                    classification = "INTERNAL"

                # Do not log the actual sensitive values because logs or reports
                # could expose the sensitive information the scanner is meant to protect
                writer.writerow([
                    original_path,
                    classification,
                    len(emails),
                    len(ssns),
                    len(valid_cards),
                    len(phone_numbers)
                ])

                # Encrypt files classified as CONFIDENTIAL
                if classification == "RESTRICTED" and not is_encrypted:
                    encrypt_file(file_path)

print("Report written to report.csv")
