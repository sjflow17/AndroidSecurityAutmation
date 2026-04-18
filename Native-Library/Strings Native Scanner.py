import os
import re
import subprocess
import shutil
from datetime import datetime

STRINGS = "strings.exe"
APKTOOL = "apktool.bat"

APK_DIR = "APK"
DECODE_DIR = "tmp_decode_strings"
OUTPUT_FILE = "strings_native_results.txt"

# Ignore noisy SDK libraries
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

# Ignore documentation / reference domains
IGNORE_DOMAINS = (
    "webrtc.org",
    "googlesource.com",
    "ietf.org",
    "github.io",
    "crbug.com",
    "comodoca.com",
    "comodo.net",
)

# High-signal patterns ONLY
PATTERNS = {
    "FIREBASE_URL": r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
    "GOOGLE_API_KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
    "JWT": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    "BACKEND_URL": r"https?://[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+/[^\s\"']{5,}",
    "EMBEDDED_CREDS": r"https?://[^/\s:@]+:[^/\s@]+@[^\s\"']+",
    "INTERNAL_IP_PORT": r"\b(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))[0-9\.]+:\d{2,5}\b",
}

def should_ignore_lib(path):
    return any(lib in path.lower() for lib in IGNORE_LIBS)

def should_ignore_domain(val):
    return any(d in val for d in IGNORE_DOMAINS)

def decode_apk(apk_path, out_dir):
    print(f"[+] Decompiling APK: {apk_path}")
    result = subprocess.run(
        [APKTOOL, "d", "-f", apk_path, "-o", out_dir],
        shell=True
    )
    return result.returncode == 0

def scan_so(so_path, report):
    if should_ignore_lib(so_path):
        return

    print(f"    [*] Scanning with strings: {so_path}")
    try:
        res = subprocess.run(
            [STRINGS, "-n", "6", so_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="ignore"
        )
    except Exception:
        return

    for line in res.stdout.splitlines():
        for label, pattern in PATTERNS.items():
            for match in re.findall(pattern, line):
                val = match if isinstance(match, str) else match[0]
                if label == "BACKEND_URL" and should_ignore_domain(val):
                    continue
                report.write(f"[{label}] {so_path} -> {val}\n")

def scan_folder(folder, report):
    for root, _, files in os.walk(folder):
        for f in files:
            if f.endswith(".so"):
                scan_so(os.path.join(root, f), report)

def main():
    os.makedirs(DECODE_DIR, exist_ok=True)

    print("\nSelect mode:")
    print("1) Scan single APK")
    print("2) Scan all APKs in APK folder")
    print("3) Scan folder recursively for .so files")
    print("4) Scan folder containing multiple APKs")
    choice = input("> ").strip()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as report:
        report.write("Strings Native Scan Results (Final)\n")
        report.write(f"Start Time: {datetime.now()}\n")
        report.write("=" * 80 + "\n\n")

        if choice == "1":
            apk = input("Enter APK path (no quotes): ").strip()
            out = os.path.join(DECODE_DIR, os.path.basename(apk))
            if decode_apk(apk, out):
                scan_folder(out, report)
            shutil.rmtree(out, ignore_errors=True)

        elif choice == "2":
            for apk in os.listdir(APK_DIR):
                if apk.endswith(".apk"):
                    out = os.path.join(DECODE_DIR, apk)
                    if decode_apk(os.path.join(APK_DIR, apk), out):
                        scan_folder(out, report)
                    shutil.rmtree(out, ignore_errors=True)

        elif choice == "3":
            folder = input("Enter folder path: ").strip()
            scan_folder(folder, report)

        elif choice == "4":
            folder = input("Enter folder containing APKs: ").strip()
            for apk in os.listdir(folder):
                if apk.endswith(".apk"):
                    out = os.path.join(DECODE_DIR, apk)
                    if decode_apk(os.path.join(folder, apk), out):
                        scan_folder(out, report)
                    shutil.rmtree(out, ignore_errors=True)

        report.write("\n" + "=" * 80 + "\n")
        report.write(f"End Time: {datetime.now()}\n")

    print(f"\n[+] Done. Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
