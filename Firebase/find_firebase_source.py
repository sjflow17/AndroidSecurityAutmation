import os
import sys

STRINGS_DIR = "strings"

if len(sys.argv) != 2:
    print("Usage: python find_firebase_source.py <firebase_url>")
    sys.exit(1)

target = sys.argv[1].rstrip("/")

print(f"[*] Searching for: {target}\n")

found = False

for file in os.listdir(STRINGS_DIR):
    if not file.lower().endswith(".xml"):
        continue

    path = os.path.join(STRINGS_DIR, file)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        if target in f.read():
            print(f"[+] Found in: {file}")
            found = True

if not found:
    print("[-] Not found in any strings.xml")
