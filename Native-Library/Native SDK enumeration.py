#!/usr/bin/env python3
import os
import re
import subprocess
import shutil
from datetime import datetime

APKTOOL = "apktool.bat"
READELF = "readelf.exe"

APK_DIR = "APK"
DECODE_DIR = "tmp_decode_native_sdks"
OUTPUT_FILE = "native_third_party_sdks.txt"

# =========================
# NOISE FILTERS
# =========================
IGNORE_LIBS = (
    "libc++",
    "libstdc++",
    "libm",
    "liblog",
    "libdl",
    "libandroid",
)

# =========================
# THIRD-PARTY SDK PATTERNS
# (HIGH SIGNAL ONLY)
# =========================
SDK_PATTERNS = {
    # Analytics / Telemetry
    "GOOGLE_ANALYTICS": r"google-analytics|analytics\.google\.com",
    "FIREBASE": r"firebase|firebaseio\.com|firebasestorage",
    "MIXPANEL": r"mixpanel",
    "AMPLITUDE": r"amplitude\.com|amplitude",

    # Ads / Attribution
    "APPSFLYER": r"appsflyer",
    "ADJUST": r"adjust\.com|adjust",
    "BRANCH": r"branch\.io",
    "FACEBOOK_SDK": r"facebook\.com|fbcdn|graph\.facebook",

    # Crash / Monitoring
    "SENTRY": r"sentry\.io|sentry",
    "BUGSNAG": r"bugsnag",
    "CRASHLYTICS": r"crashlytics",

    # Cloud / Infra
    "AWS": r"amazonaws\.com|aws",
    "GCP": r"googleapis\.com",
    "AZURE": r"azure\.com",

    # Payments
    "STRIPE": r"stripe\.com|stripe",
    "PAYPAL": r"paypal\.com|braintree",

    # Risk / Fraud
    "THREATMETRIX": r"threatmetrix",
    "ARKOSE_LABS": r"arkoselabs",
    "PERIMETERX": r"perimeterx",

    # Social / Auth
    "GOOGLE_SIGNIN": r"accounts\.google\.com",
    "FACEBOOK_LOGIN": r"facebook\.com/login",
}

# =========================
# HELPERS
# =========================
def should_ignore_lib(path):
    return any(lib in path.lower() for lib in IGNORE_LIBS)

def decode_apk(apk_path, out_dir):
    print(f"[+] Decompiling APK: {apk_path}")
    res = subprocess.run(
        f'{APKTOOL} d -f "{apk_path}" -o "{out_dir}"',
        shell=True
    )
    return res.returncode == 0

def run_readelf(so_path):
    try:
        res = subprocess.run(
            [READELF, "-p", ".rodata", so_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="ignore"
        )
        return res.stdout
    except Exception:
        return ""

# =========================
# CORE SCAN (DEDUP)
# =========================
def scan_so(so_path, findings, report):
    if should_ignore_lib(so_path):
        return

    print(f"    [*] Scanning: {so_path}")
    data = run_readelf(so_path)
    if not data:
        return

    for label, pattern in SDK_PATTERNS.items():
        if re.search(pattern, data, re.IGNORECASE):
            key = (label, so_path)
            if key not in findings:
                findings.add(key)
                report.write(f"[{label}] Detected in {so_path}\n")

def scan_folder(folder, findings, report):
    for root, _, files in os.walk(folder):
        for f in files:
            if f.endswith(".so"):
                scan_so(os.path.join(root, f), findings, report)

# =========================
# MAIN
# =========================
def main():
    os.makedirs(DECODE_DIR, exist_ok=True)
    findings = set()

    print("\nSelect mode:")
    print("1) Scan single APK")
    print("2) Scan all APKs in APK folder")
    print("3) Scan folder recursively for .so files")
    print("4) Scan folder containing multiple APKs")
    choice = input("> ").strip()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as report:
        report.write("Native Third-Party SDK Identification\n")
        report.write(f"Start Time: {datetime.now()}\n")
        report.write("=" * 80 + "\n\n")

        if choice == "1":
            apk = input("Enter APK path: ").strip()
            out = os.path.join(DECODE_DIR, os.path.basename(apk))
            if decode_apk(apk, out):
                scan_folder(out, findings, report)
            shutil.rmtree(out, ignore_errors=True)

        elif choice == "2":
            for apk in os.listdir(APK_DIR):
                if apk.endswith(".apk"):
                    out = os.path.join(DECODE_DIR, apk)
                    if decode_apk(os.path.join(APK_DIR, apk), out):
                        scan_folder(out, findings, report)
                    shutil.rmtree(out, ignore_errors=True)

        elif choice == "3":
            folder = input("Enter folder path: ").strip()
            scan_folder(folder, findings, report)

        elif choice == "4":
            folder = input("Enter folder with APKs: ").strip()
            for apk in os.listdir(folder):
                if apk.endswith(".apk"):
                    out = os.path.join(DECODE_DIR, apk)
                    if decode_apk(os.path.join(folder, apk), out):
                        scan_folder(out, findings, report)
                    shutil.rmtree(out, ignore_errors=True)

        report.write("\n" + "=" * 80 + "\n")
        report.write(f"End Time: {datetime.now()}\n")

    print(f"\n[+] Done. Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
