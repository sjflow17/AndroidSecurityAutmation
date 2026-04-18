import os
import re
import subprocess
import shutil
from datetime import datetime

APK_DIR = "APK"
DECODE_DIR = "tmp_decode_hardcoded"
OUTPUT_FILE = "hardcoded_source_results.txt"
APKTOOL_CMD = "apktool.bat"

SCAN_EXTENSIONS = (
    ".smali",
    ".xml",
    ".json",
    ".properties",
    ".env",
    ".yml",
    ".yaml"
)

IGNORE_URLS = (
    "schemas.android.com",
    "schema.android",
)

# =========================
# HIGH-SIGNAL PATTERNS
# =========================
PATTERNS = {
    # Existing
    "FIREBASE_URL": r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
    "BACKEND_URL": r"https?://[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+/[^\s\"']{5,}",
    "GOOGLE_API_KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "JWT": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "EMBEDDED_CREDS": r"https?://[^/\s:@]+:[^/\s@]+@[^\s\"']+",
    "AWS_SECRET_KEY": r"(?i)aws(.{0,20})?(secret|private)[\"'\s:=]{1,5}[A-Za-z0-9/+=]{40}",
    "SLACK_TOKEN": r"xox[baprs]-[A-Za-z0-9\-]{10,}",
    "GITHUB_TOKEN": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "STRIPE_KEY": r"sk_live_[0-9a-zA-Z]{24}",

    # =========================
    # ANDROID DEEP LINK PATTERNS
    # =========================

    # Custom scheme deep links
    "CUSTOM_SCHEME": r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,30}://[a-zA-Z0-9/_\-?.=&%]+",

    # Intent URI
    "INTENT_URI": r"intent://[^\s\"']+",

    # FTP links
    "FTP_URL": r"ftp://[^\s\"']+",

    # Manifest deep link components
    "ANDROID_SCHEME": r'android:scheme="[^"]+"',
    "ANDROID_HOST": r'android:host="[^"]+"',
    "ANDROID_PATH": r'android:path[^=]*="[^"]+"',
}

# =========================
# HELPERS
# =========================
def should_ignore(match: str) -> bool:
    return any(x in match for x in IGNORE_URLS)

def decode_apk(apk_path, out_dir):
    print(f"[+] Decompiling: {apk_path}")
    result = subprocess.run(
        f'{APKTOOL_CMD} d -f "{apk_path}" -o "{out_dir}"',
        shell=True
    )
    return result.returncode == 0

# =========================
# SCANNING LOGIC (DEDUP)
# =========================
def scan_file(file_path, findings: set):
    print(f"    [*] Scanning: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                for label, pattern in PATTERNS.items():
                    for match in re.findall(pattern, line):
                        value = match if isinstance(match, str) else match[0]
                        if should_ignore(value):
                            continue

                        # Dedup key (label + value)
                        key = (label, value)
                        if key not in findings:
                            findings.add(key)
                            yield f"[{label}] {file_path}:{line_no} -> {value}"
    except Exception:
        return

def scan_decoded_folder(folder, findings, report):
    found_any = False
    for root, _, files in os.walk(folder):
        for file in files:
            if file.lower().endswith(SCAN_EXTENSIONS):
                for result in scan_file(os.path.join(root, file), findings):
                    report.write(result + "\n")
                    found_any = True
    if not found_any:
        print("    [-] No relevant files found")

# =========================
# APK SELECTION
# =========================
def get_apk_list():
    print("\nSelect mode:")
    print("1) Scan one APK manually")
    print("2) Scan all APKs in APK folder")
    choice = input("> ").strip()

    if choice == "1":
        apk = input("Enter full path to APK (no quotes): ").strip()
        return [apk] if os.path.isfile(apk) else []
    else:
        return [
            os.path.join(APK_DIR, f)
            for f in os.listdir(APK_DIR)
            if f.lower().endswith(".apk")
        ]

# =========================
# MAIN
# =========================
def main():
    os.makedirs(DECODE_DIR, exist_ok=True)
    apks = get_apk_list()

    if not apks:
        print("[-] No APKs selected")
        return

    findings = set()  # 🔑 GLOBAL DEDUP STORE

    with open(OUTPUT_FILE, "w", encoding="utf-8") as report:
        report.write("Hardcoded Source & Deep Link Scan Results\n")
        report.write(f"Start Time: {datetime.now()}\n")
        report.write("=" * 80 + "\n\n")

        for apk_path in apks:
            apk_name = os.path.basename(apk_path)
            decode_path = os.path.join(DECODE_DIR, apk_name)

            print(f"\n[+] Processing APK: {apk_name}")
            report.write(f"[APK] {apk_name}\n")
            report.write("-" * 80 + "\n")

            if decode_apk(apk_path, decode_path):
                scan_decoded_folder(decode_path, findings, report)
            else:
                report.write("[-] Failed to decode APK\n")

            shutil.rmtree(decode_path, ignore_errors=True)
            report.write("\n")

        report.write("=" * 80 + "\n")
        report.write(f"End Time: {datetime.now()}\n")

    print(f"\n[+] Done. Unique results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
