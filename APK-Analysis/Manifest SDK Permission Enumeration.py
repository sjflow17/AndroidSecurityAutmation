#!/usr/bin/env python3
import os
import subprocess
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime

APKTOOL = "apktool.bat"
APK_DIR = "APK"
DECODE_DIR = "tmp_decode_permissions"
OUTPUT_FILE = "m2_step3_permission_analysis.txt"

os.makedirs(DECODE_DIR, exist_ok=True)

# =========================
# DANGEROUS PERMISSIONS
# =========================
DANGEROUS_PERMISSIONS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "READ_CALL_LOG", "READ_PHONE_STATE",
    "RECORD_AUDIO", "CAMERA",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "BODY_SENSORS",
}

# =========================
# SDK PERMISSION HEURISTICS
# =========================
SDK_PERMISSION_RISK = {
    "Analytics / Attribution": {
        "keywords": ["adjust", "appsflyer", "firebase", "mixpanel", "amplitude"],
        "risky_permissions": {
            "READ_PHONE_STATE", "ACCESS_FINE_LOCATION",
            "ACCESS_COARSE_LOCATION", "READ_SMS"
        }
    },
    "Ads / Tracking": {
        "keywords": ["facebook", "admob", "unityads"],
        "risky_permissions": {
            "READ_PHONE_STATE", "ACCESS_FINE_LOCATION", "CAMERA"
        }
    },
    "Crash Reporting": {
        "keywords": ["sentry", "crashlytics"],
        "risky_permissions": set()
    }
}

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

def extract_permissions(manifest_path):
    perms = set()
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    for elem in root.findall("uses-permission"):
        name = elem.attrib.get("{http://schemas.android.com/apk/res/android}name")
        if name:
            perms.add(name.split(".")[-1])
    return perms

def detect_sdks_from_manifest(manifest_path):
    data = open(manifest_path, errors="ignore").read().lower()
    detected = set()

    for category, meta in SDK_PERMISSION_RISK.items():
        for k in meta["keywords"]:
            if k in data:
                detected.add(category)
    return detected

# =========================
# ANALYSIS
# =========================
def analyze_apk(apk_path, report):
    out_dir = os.path.join(DECODE_DIR, os.path.basename(apk_path))
    if not decode_apk(apk_path, out_dir):
        return

    manifest = os.path.join(out_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest):
        shutil.rmtree(out_dir, ignore_errors=True)
        return

    permissions = extract_permissions(manifest)
    dangerous = permissions.intersection(DANGEROUS_PERMISSIONS)
    sdk_categories = detect_sdks_from_manifest(manifest)

    report.write(f"APK: {apk_path}\n")
    report.write("-" * 70 + "\n")

    report.write("Declared Permissions:\n")
    for p in sorted(permissions):
        report.write(f"  - {p}\n")

    report.write("\nDangerous Permissions:\n")
    if dangerous:
        for d in sorted(dangerous):
            report.write(f"  ! {d}\n")
    else:
        report.write("  None\n")

    report.write("\nDetected SDK Categories:\n")
    if sdk_categories:
        for s in sdk_categories:
            report.write(f"  - {s}\n")
    else:
        report.write("  None\n")

    report.write("\nHeuristic Risk Flags:\n")
    for category in sdk_categories:
        risky = SDK_PERMISSION_RISK[category]["risky_permissions"]
        overlap = dangerous.intersection(risky)
        if overlap:
            report.write(
                f"  [!] {category} + {', '.join(overlap)} → review required\n"
            )

    report.write("\n\n")
    shutil.rmtree(out_dir, ignore_errors=True)
    print("    [*] Permission analysis completed.\n")

# =========================
# MAIN
# =========================
def main():
    with open(OUTPUT_FILE, "w", encoding="utf-8") as report:
        report.write("OWASP M2 – Step 3: Permission & Capability Analysis\n")
        report.write(f"Start Time: {datetime.now()}\n")
        report.write("=" * 80 + "\n\n")

        for apk in os.listdir(APK_DIR):
            if apk.endswith(".apk"):
                analyze_apk(os.path.join(APK_DIR, apk), report)

        report.write("=" * 80 + "\n")
        report.write(f"End Time: {datetime.now()}\n")

    print(f"[+] Analysis complete. Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
