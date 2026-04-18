#!/usr/bin/env python3
import os
import re
import subprocess
import shutil
import requests
from datetime import datetime

# =========================
# CONFIGURATION
# =========================
APKTOOL = "apktool.bat"
APK_DIR = "APK"
DECODE_DIR = "tmp_decode_debug"
OUTPUT_FILE = "debug_cloud_endpoints.txt"
TIMEOUT = 6

os.makedirs(DECODE_DIR, exist_ok=True)

# =========================
# HIGH-SIGNAL ENDPOINT PATTERNS
# =========================
PATTERNS = {
    "AWS_S3": r"https?://[a-z0-9.\-]+\.s3\.amazonaws\.com",
    "AWS_API": r"https?://[a-z0-9\-]+\.execute-api\.[a-z0-9\-]+\.amazonaws\.com",
    "CLOUDFRONT": r"https?://[a-z0-9.\-]+\.cloudfront\.net",

    "FIREBASE": r"https?://[a-z0-9\-]+\.firebaseio\.com",
    "GCP_API": r"https?://[a-z0-9.\-]+\.googleapis\.com",

    "APPSPOT": r"https?://[a-z0-9\-]+\.appspot\.com",

    "DEBUG_ENV": r"https?://[^\"'\s]+(dev|staging|qa|test|sandbox|internal)[^\"'\s]*",
}

SCAN_EXT = (".xml", ".smali", ".json", ".txt")

# =========================
# HELPER FUNCTIONS
# =========================
def decode_apk(apk_path, out_dir):
    print(f"[+] Decompiling APK: {apk_path}")
    res = subprocess.run(
        f'{APKTOOL} d -f "{apk_path}" -o "{out_dir}"',
        shell=True
    )
    return res.returncode == 0

def classify_env(url):
    for k in ["dev", "staging", "qa", "test", "sandbox", "internal"]:
        if k in url.lower():
            return "NON_PROD"
    return "PROD"

def validate(url):
    try:
        r = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
        return r.status_code
    except Exception:
        return "NO_RESPONSE"

# =========================
# CORE SCAN FUNCTION
# =========================
def scan_decompiled(folder, findings, report):
    file_count = 0
    print("    [*] Scanning decompiled files for endpoints...")

    for root, _, files in os.walk(folder):
        for f in files:
            if not f.endswith(SCAN_EXT):
                continue

            file_count += 1
            if file_count % 500 == 0:
                print(f"        [+] Scanned {file_count} files...")

            path = os.path.join(root, f)
            try:
                data = open(path, errors="ignore").read()
            except Exception:
                continue

            for label, rx in PATTERNS.items():
                for m in re.findall(rx, data, re.IGNORECASE):
                    key = (label, m)
                    if key not in findings:
                        findings.add(key)

                        print(f"        [!] Found {label}: {m}")
                        env = classify_env(m)
                        status = validate(m)

                        report.write(f"[{label}] {m}\n")
                        report.write(f"  Environment: {env}\n")
                        report.write(f"  HTTP Status: {status}\n\n")

    print(f"    [*] Completed scan of {file_count} files.")

# =========================
# MAIN EXECUTION
# =========================
def main():
    findings = set()

    print("\nSelect mode:")
    print("1) Scan single APK")
    print("2) Scan all APKs in APK folder")
    print("3) Scan already decompiled folder")
    print("4) Scan folder containing multiple APKs")
    choice = input("> ").strip()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as report:
        report.write("Debug / Cloud Endpoint Enumeration\n")
        report.write(f"Start Time: {datetime.now()}\n")
        report.write("=" * 80 + "\n\n")

        if choice == "1":
            apk = input("Enter APK path: ").strip()
            out = os.path.join(DECODE_DIR, os.path.basename(apk))
            if decode_apk(apk, out):
                scan_decompiled(out, findings, report)
            shutil.rmtree(out, ignore_errors=True)

        elif choice == "2":
            for apk in os.listdir(APK_DIR):
                if apk.endswith(".apk"):
                    out = os.path.join(DECODE_DIR, apk)
                    if decode_apk(os.path.join(APK_DIR, apk), out):
                        scan_decompiled(out, findings, report)
                    shutil.rmtree(out, ignore_errors=True)
                    print("    [*] Cleanup complete, moving to next APK.\n")

        elif choice == "3":
            folder = input("Enter decompiled folder path: ").strip()
            scan_decompiled(folder, findings, report)

        elif choice == "4":
            folder = input("Enter folder with APKs: ").strip()
            for apk in os.listdir(folder):
                if apk.endswith(".apk"):
                    out = os.path.join(DECODE_DIR, apk)
                    if decode_apk(os.path.join(folder, apk), out):
                        scan_decompiled(out, findings, report)
                    shutil.rmtree(out, ignore_errors=True)
                    print("    [*] Cleanup complete, moving to next APK.\n")

        else:
            print("Invalid option")
            return

        report.write("=" * 80 + "\n")
        report.write(f"End Time: {datetime.now()}\n")

    print(f"\n[+] Scan complete. Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
