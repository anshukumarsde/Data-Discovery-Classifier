import os
import sys

for root, dirs, files in os.walk(sys.argv[1]):
    for file in files:
        print(os.path.join(root, file))