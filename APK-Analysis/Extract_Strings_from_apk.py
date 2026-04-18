import os
import subprocess
import shutil
import time
import stat

APK_DIR = "APK"
STRINGS_DIR = "Strings"
TMP_DIR = "tmp_decode"

TIMEOUT_SECONDS = 120
APKTOOL = "apktool.bat" if os.name == "nt" else "apktool"

os.makedirs(STRINGS_DIR, exist_ok=True)
os.makedirs(TMP_DIR, exist_ok=True)


def get_package_name(apk_path):
    try:
        output = subprocess.check_output(
            ["aapt", "dump", "badging", apk_path],
            stderr=subprocess.DEVNULL,
            text=True
        )
        for line in output.splitlines():
            if line.startswith("package:"):
                return line.split("name='")[1].split("'")[0]
    except Exception:
        pass
    return os.path.basename(apk_path).replace(".apk", "")


def force_delete(path, retries=5, delay=2):
    """
    Robust Windows-safe directory deletion
    """
    def onerror(func, path, exc_info):
        os.chmod(path, stat.S_IWRITE)
        func(path)

    for attempt in range(retries):
        try:
            shutil.rmtree(path, onerror=onerror)
            return True
        except Exception:
            time.sleep(delay)
    return False


print("[*] Extracting strings.xml from APKs (timeout-aware, Windows-safe)\n")

for apk in os.listdir(APK_DIR):
    if not apk.lower().endswith(".apk"):
        continue

    apk_path = os.path.join(APK_DIR, apk)
    print(f"[+] Processing {apk}")

    package = get_package_name(apk_path)
    decode_dir = os.path.join(TMP_DIR, package)
    strings_xml = os.path.join(decode_dir, "res", "values", "strings.xml")

    process = subprocess.Popen(
        [APKTOOL, "d", "--no-src", "-f", apk_path, "-o", decode_dir],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    start = time.time()
    extracted = False

    while time.time() - start < TIMEOUT_SECONDS:
        if os.path.exists(strings_xml):
            dest = os.path.join(STRINGS_DIR, f"{package} Strings.xml")
            shutil.copy(strings_xml, dest)
            print(f"    [+] Extracted → {dest}")
            extracted = True
            break
        time.sleep(1)

    if not extracted:
        print("    [-] Timeout reached, strings.xml not found")

    # Kill apktool HARD
    if process.poll() is None:
        process.kill()
        process.wait()

    # Cleanup safely
    if os.path.exists(decode_dir):
        if force_delete(decode_dir):
            print("    [✓] Cleaned decoded resources")
        else:
            print("    [!] Failed to clean decoded resources (locked by OS)")

print("\n[✓] Extraction completed safely")
