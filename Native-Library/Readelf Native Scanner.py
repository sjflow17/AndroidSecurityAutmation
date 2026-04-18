import os
import re
import subprocess
import shutil
from datetime import datetime

APKTOOL = "apktool.bat"
READELF = "readelf.exe"

APK_DIR = "APK"
DECODE_DIR = "tmp_decode_readelf"
OUTPUT_FILE = "readelf_native_results.txt"

# =========================
# NOISE FILTERS
# =========================
IGNORE_LIBS = (
    "libtwilio",
    "libwebrtc",
    "libc++",
    "libfolly",
    "libreact",
    "libsentry",
    "libfb",
    "libhermes",
)

IGNORE_DOMAINS = (
    "webrtc.org",
    "googlesource.com",
    "ietf.org",
    "github.io",
    "crbug.com",
    "comodoca.com",
    "comodo.net",
)

# =========================
# HIGH-SIGNAL PATTERNS
# =========================
PATTERNS = {
    # Credentials / secrets
    "FIREBASE_URL": r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
    "GOOGLE_API_KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
    "JWT": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "EMBEDDED_CREDS": r"https?://[^/\s:@]+:[^/\s@]+@[^\s\"']+",

    # Backend URLs (FULL only, never partial)
    "BACKEND_URL": r"https?://[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+/[^\s\"']{5,}",

    # =========================
    # ANDROID DEEP LINKS
    # =========================

    # Custom scheme deep links
    "CUSTOM_SCHEME": r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,30}://[a-zA-Z0-9/_\-?.=&%]+",

    # Intent URIs
    "INTENT_URI": r"intent://[^\s\"']+",

    # FTP URLs
    "FTP_URL": r"ftp://[^\s\"']+",

    # Manifest attributes (can appear in native strings too)
    "ANDROID_SCHEME": r'android:scheme="[^"]+"',
    "ANDROID_HOST": r'android:host="[^"]+"',
    "ANDROID_PATH": r'android:path[^=]*="[^"]+"',
}

# =========================
# HELPERS
# =========================
def should_ignore_lib(path):
    return any(x in path.lower() for x in IGNORE_LIBS)

def should_ignore_domain(val):
    return any(d in val for d in IGNORE_DOMAINS)

def decode_apk(apk_path, out_dir):
    print(f"[+] Decompiling APK: {apk_path}")
    result = subprocess.run(
        f'{APKTOOL} d -f "{apk_path}" -o "{out_dir}"',
        shell=True
    )
    return result.returncode == 0

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

    for label, pattern in PATTERNS.items():
        for match in re.findall(pattern, data):
            value = match if isinstance(match, str) else match[0]

            if label == "BACKEND_URL" and should_ignore_domain(value):
                continue

            key = (label, value)
            if key not in findings:
                findings.add(key)
                report.write(f"[{label}] {so_path} -> {value}\n")

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
    findings = set()  # 🔑 GLOBAL DEDUP

    print("\nSelect mode:")
    print("1) Scan single APK")
    print("2) Scan all APKs in APK folder")
    print("3) Scan folder recursively for .so files")
    print("4) Scan folder containing multiple APKs")
    choice = input("> ").strip()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as report:
        report.write("Readelf Native Scan Results (Deduplicated)\n")
        report.write(f"Start Time: {datetime.now()}\n")
        report.write("=" * 80 + "\n\n")

        if choice == "1":
            apk = input("Enter APK path (no quotes): ").strip()
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

    print(f"\n[+] Done. Unique results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
