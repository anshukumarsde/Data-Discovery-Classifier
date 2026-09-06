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
import csv

# Sensitive-data patterns
EMAIL_PATTERN = r"\S+@\S+\.\S+"
SSN_PATTERN = r"\d{3}-\d{2}-\d{4}"
CARD_PATTERN = r"\d{16}"
PHONE_PATTERN = r"\d{3}-\d{3}-\d{4}"

# File extensions that will be treated as text files
TEXT_EXTENSIONS = [".txt", ".csv", ".json", ".xml", ".log"]

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
                    file_path,
                    classification,
                    len(emails),
                    len(ssns),
                    len(valid_cards),
                    len(phone_numbers)
                ])
    print("Report written to report.csv")