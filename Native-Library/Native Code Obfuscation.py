#!/usr/bin/env python3
import os
import subprocess
import shutil
import re
from datetime import datetime

APKTOOL = "apktool.bat"
APK_DIR = "APK"
DECODE_DIR = "tmp_decode_step4"
OUTPUT_FILE = "m2_step4_code_trust_analysis.txt"

os.makedirs(DECODE_DIR, exist_ok=True)

# =========================
# HIGH-RISK PATTERNS
# =========================
SMALI_PATTERNS = {
    "Dynamic_Code_Loading": [
        "Ldalvik/system/DexClassLoader;",
        "Ldalvik/system/PathClassLoader;"
    ],
    "Reflection_Usage": [
        "Ljava/lang/Class;->forName",
        "Ljava/lang/reflect/Method;->invoke",
        "Ljava/lang/reflect/Field;->get"
    ],
    "Crypto_Usage": [
        "Ljavax/crypto/Cipher;",
        "Ljavax/crypto/spec/SecretKeySpec;",
        "Ljava/security/MessageDigest;",
        "android/util/Base64"
    ]
}

NATIVE_KEYWORDS = [
    "JNI_OnLoad", "dlopen", "dlsym",
    "socket", "connect", "send", "recv"
]

DYNAMIC_PERMISSIONS = {
    "REQUEST_INSTALL_PACKAGES",
    "INSTALL_PACKAGES"
}

SCAN_SMALI_LIMIT = 3000

# =========================
# HELPERS
# =========================
def decode_apk(apk_path, out_dir):
    print(f"[+] Decompiling APK: {apk_path}")
    res = subprocess.run(
        f'{APKTOOL} d -f "{apk_path}" -o "{out_dir}"',
        shell=True
    )
    return res.returncode == 0

# =========================
# ANALYSIS LOGIC
# =========================
def scan_step4(decode_dir, report):
    report.write("Native Code Analysis:\n")
    native_found = False

    for root, _, files in os.walk(decode_dir):
        for f in files:
            if f.endswith(".so"):
                native_found = True
                path = os.path.join(root, f)
                report.write(f"  - Found native library: {f}\n")

                try:
                    data = open(path, "rb").read()
                    for k in NATIVE_KEYWORDS:
                        if k.encode() in data:
                            report.write(f"      [!] Native keyword detected: {k}\n")
                except Exception:
                    report.write("      [!] Unable to read native binary\n")

    if not native_found:
        report.write("  None detected\n")
    report.write("\n")

    report.write("Smali Code Risk Signals:\n")
    smali_count = 0
    hits = False

    for root, _, files in os.walk(decode_dir):
        for f in files:
            if not f.endswith(".smali"):
                continue

            smali_count += 1
            if smali_count > SCAN_SMALI_LIMIT:
                report.write("  [*] Smali scan limit reached (sampling applied)\n")
                break

            path = os.path.join(root, f)
            try:
                data = open(path, errors="ignore").read()
            except Exception:
                continue

            for category, patterns in SMALI_PATTERNS.items():
                for p in patterns:
                    if p in data:
                        report.write(f"  [!] {category} detected in {f}\n")
                        hits = True

    if not hits:
        report.write("  No high-risk smali patterns detected\n")
    report.write("\n")

    report.write("Manifest Trust Signals:\n")
    manifest = os.path.join(decode_dir, "AndroidManifest.xml")

    if os.path.exists(manifest):
        data = open(manifest, errors="ignore").read()
        found = False

        for p in DYNAMIC_PERMISSIONS:
            if p in data:
                report.write(f"  [!] Dynamic install permission detected: {p}\n")
                found = True

        if "<uses-library" in data:
            report.write("  [!] uses-library directive present\n")
            found = True

        if not found:
            report.write("  No high-risk manifest signals detected\n")
    else:
        report.write("  Manifest not found\n")

    report.write("\n")

# =========================
# MODE HANDLERS
# =========================
def analyze_single_apk(apk_path, report):
    out = os.path.join(DECODE_DIR, os.path.basename(apk_path))
    if decode_apk(apk_path, out):
        scan_step4(out, report)
    shutil.rmtree(out, ignore_errors=True)

def analyze_apk_folder(folder, report):
    for apk in os.listdir(folder):
        if apk.endswith(".apk"):
            analyze_single_apk(os.path.join(folder, apk), report)

# =========================
# MAIN
# =========================
def main():
    print("\nSelect mode:")
    print("1) Scan single APK")
    print("2) Scan all APKs in APK folder")
    print("3) Scan already decompiled folder")
    print("4) Scan folder containing multiple APKs")
    choice = input("> ").strip()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as report:
        report.write("OWASP M2 – Step 4: Code Integrity & Trustworthiness\n")
        report.write(f"Start Time: {datetime.now()}\n")
        report.write("=" * 80 + "\n\n")

        if choice == "1":
            apk = input("Enter APK path: ").strip()
            analyze_single_apk(apk, report)

        elif choice == "2":
            analyze_apk_folder(APK_DIR, report)

        elif choice == "3":
            folder = input("Enter decompiled folder path: ").strip()
            scan_step4(folder, report)

        elif choice == "4":
            folder = input("Enter folder with APKs: ").strip()
            analyze_apk_folder(folder, report)

        else:
            print("Invalid option")
            return

        report.write("=" * 80 + "\n")
        report.write(f"End Time: {datetime.now()}\n")

    print(f"[+] Step 4 analysis complete. Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
