"""
Data Discovery Classifier - Directory Scanner

Walks through a directory, reads text-like files, and scans them
for sensitive data such as email addresses, SSNs, credit card
numbers, and phone numbers.

test_data/subfolder/file3.txt is there to prove that os.walk() does scan nested
directories recursively. 

Usage:
    python scanner.py <directory>
"""

import os
import sys
import re

# Sensitive-data patterns
EMAIL_PATTERN = r"\S+@\S+\.\S+"
SSN_PATTERN = r"\d{3}-\d{2}-\d{4}"
CARD_PATTERN = r"\d{16}"
PHONE_PATTERN = r"\d{3}-\d{3}-\d{4}"

# File extensions that will be treated as text files
TEXT_EXTENSIONS = [".txt", ".csv", ".json", ".xml", ".log"]

for root, _, files in os.walk(sys.argv[1]):
    for file in files:
        file_path = os.path.join(root, file)
        # Only scan text_like files
        if os.path.splitext(file)[1].lower() in TEXT_EXTENSIONS:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            emails = re.findall(EMAIL_PATTERN, content)
            ssns = re.findall(SSN_PATTERN, content)
            cards = re.findall(CARD_PATTERN, content)
            phone_numbers = re.findall(PHONE_PATTERN, content)

            print(file_path)
            print("Emails:", len(emails))
            print("SSNs:", len(ssns))
            print("Credit Cards:", len(cards))
            print("Phone Numbers:", len(phone_numbers))
            print()