"""
Data Discovery Classifier - Directory Scanner

Walks through a directory provided as a command-line argument
and prints the path of every file found, including files in subdirectories.

Usage:
    python scanner.py test_data

os.walk() returns:
- root: the current directory being visited
- dirs: the subdirectories inside the current directory
- files: the files inside the current directory
"""

import os
import sys

for root, dirs, files in os.walk(sys.argv[1]):
    for file in files:
        print(os.path.join(root, file))