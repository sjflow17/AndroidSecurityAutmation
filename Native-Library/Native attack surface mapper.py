#!/usr/bin/env python3
import os
import re
import subprocess
import shutil
from datetime import datetime

# =========================
# CONFIG (MATCHES YOUR TOOLS)
# =========================
APKTOOL = "apktool.bat"
READELF = "readelf.exe"

APK_DIR = "APK"
DECODE_DIR = "tmp_decode_jni"
OUTPUT_FILE = "jni_native_attack_surface.txt"

os.makedirs(DECODE_DIR, exist_ok=True)

# =========================
# JNI / NATIVE RISK SIGNALS
# =========================
UNSAFE_NATIVE_FUNCS = [
    "strcpy", "strcat", "sprintf", "vsprintf",
    "gets", "memcpy", "memmove", "scanf"
]

JNI_KEYWORDS = [
    "JNI_OnLoad",
    "RegisterNatives",
    "GetStringUTFChars",
    "GetByteArrayElements",
    "ReleaseStringUTFChars"
]

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

def run_readelf(so_path):
    try:
        res = subprocess.run(
            [READELF, "-Ws", so_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="ignore"
        )
        return res.stdout
    except Exception:
        return ""

# =========================
# JAVA SIDE ANALYSIS
# =========================
def scan_java_native_methods(folder, report, findings):
    report.write("Java Native Method Declarations:\n")
    found = False

    for root, _, files in os.walk(folder):
        for f in files:
            if f.endswith(".java"):
                path = os.path.join(root, f)
                try:
                    for line in open(path, errors="ignore"):
                        if " native " in line or line.strip().startswith("native "):
                            found = True
                            key = ("JAVA_NATIVE", path, line.strip())
                            if key not in findings:
                                findings.add(key)
                                report.write(f"[JAVA] {path} -> {line.strip()}\n")
                except Exception:
                    pass

    if not found:
        report.write("  None found\n")
    report.write("\n")

def scan_loadlibrary(folder, report, findings):
    report.write("Loaded Native Libraries:\n")
    found = False
    pattern = re.compile(r'loadLibrary\("([^"]+)"\)')

    for root, _, files in os.walk(folder):
        for f in files:
            if f.endswith(".java"):
                data = open(os.path.join(root, f), errors="ignore").read()
                for lib in pattern.findall(data):
                    found = True
                    key = ("LOAD_LIB", lib)
                    if key not in findings:
                        findings.add(key)
                        report.write(f"[LIB] {lib}\n")

    if not found:
        report.write("  None detected\n")
    report.write("\n")

# =========================
# NATIVE SIDE ANALYSIS
# =========================
def scan_native_libs(folder, report, findings):
    report.write("Native Library Risk Signals:\n")
    found = False

    for root, _, files in os.walk(folder):
        for f in files:
            if f.endswith(".so"):
                so_path = os.path.join(root, f)
                found = True
                report.write(f"\n[SO] {so_path}\n")

                data = run_readelf(so_path)
                if not data:
                    report.write("  [!] Unable to analyze symbols\n")
                    continue

                for func in UNSAFE_NATIVE_FUNCS:
                    if func in data:
                        key = ("UNSAFE_FUNC", so_path, func)
                        if key not in findings:
                            findings.add(key)
                            report.write(f"  [RISK] Unsafe function: {func}\n")

                for jni in JNI_KEYWORDS:
                    if jni in data:
                        key = ("JNI_SYMBOL", so_path, jni)
                        if key not in findings:
                            findings.add(key)
                            report.write(f"  [JNI] Symbol detected: {jni}\n")

    if not found:
        report.write("  No native libraries found\n")

    report.write("\n")

# =========================
# CORE ANALYSIS
# =========================
def analyze_folder(folder, report, findings):
    scan_java_native_methods(folder, report, findings)
    scan_loadlibrary(folder, report, findings)
    scan_native_libs(folder, report, findings)

# =========================
# MODES
# =========================
def analyze_single_apk(apk, report, findings):
    out = os.path.join(DECODE_DIR, os.path.basename(apk))
    if decode_apk(apk, out):
        analyze_folder(out, report, findings)
    shutil.rmtree(out, ignore_errors=True)

def analyze_apk_folder(folder, report, findings):
    for apk in os.listdir(folder):
        if apk.endswith(".apk"):
            analyze_single_apk(os.path.join(folder, apk), report, findings)

# =========================
# MAIN
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
        report.write("JNI & Native Attack Surface Mapping\n")
        report.write(f"Start Time: {datetime.now()}\n")
        report.write("=" * 80 + "\n\n")

        if choice == "1":
            apk = input("Enter APK path: ").strip()
            analyze_single_apk(apk, report, findings)

        elif choice == "2":
            analyze_apk_folder(APK_DIR, report, findings)

        elif choice == "3":
            folder = input("Enter decompiled folder path: ").strip()
            analyze_folder(folder, report, findings)

        elif choice == "4":
            folder = input("Enter folder with APKs: ").strip()
            analyze_apk_folder(folder, report, findings)

        else:
            print("Invalid option")
            return

        report.write("\n" + "=" * 80 + "\n")
        report.write(f"End Time: {datetime.now()}\n")

    print(f"\n[+] Done. Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
