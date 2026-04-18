import os
import xml.etree.ElementTree as ET
import pandas as pd
import subprocess
import shutil

# ==============================
# CONFIGURATION
# ==============================
MANIFEST_DIR = r"D:\Zerozeta APKS\Manifests"
APK_DIR = "APK"
TMP_DECODE_DIR = "tmp_manifest_decode"

APKTOOL = "apktool.bat"   # change to "apktool" if on Linux

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# ==============================
# HELPERS
# ==============================
def get_attr(elem, name):
    return elem.attrib.get(name) or elem.attrib.get(f'{{{ANDROID_NS}}}{name}') or "N/A"

def is_exported(elem):
    exported_attr = get_attr(elem, "exported")
    if exported_attr != "N/A":
        return exported_attr.lower() == "true"
    if elem.find("intent-filter") is not None:
        return True
    return False

def decode_apk(apk_path, out_dir):
    print(f"[+] Decompiling APK: {apk_path}")
    res = subprocess.run(
        f'{APKTOOL} d -f "{apk_path}" -o "{out_dir}"',
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return res.returncode == 0

# ==============================
# MANIFEST PARSER
# ==============================
def parse_manifest(manifest_path, app_name, data):
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        tree = ET.ElementTree(ET.fromstring(content))
        root = tree.getroot()

        package_name = get_attr(root, "package")
        version_name = get_attr(root, "versionName")
        version_code = get_attr(root, "versionCode")

        sdk = root.find("uses-sdk")
        min_sdk = target_sdk = "N/A"

        if sdk is not None:
            min_sdk = get_attr(sdk, "minSdkVersion")
            target_sdk = get_attr(sdk, "targetSdkVersion")

        compile_sdk = get_attr(root, "compileSdkVersion")
        build_version = get_attr(root, "platformBuildVersionCode")

        activities = root.findall(".//activity")
        services = root.findall(".//service")
        providers = root.findall(".//provider")

        data.append({
            "App File": app_name,
            "Package Name": package_name,
            "Version Name": version_name,
            "Version Code": version_code,
            "Compile SDK": compile_sdk,
            "Platform Build Version": build_version,
            "Min SDK": min_sdk,
            "Target SDK": target_sdk,
            "Activities Count": len(activities),
            "Exported Activities Count": sum(1 for a in activities if is_exported(a)),
            "Services Count": len(services),
            "Exported Services Count": sum(1 for s in services if is_exported(s)),
            "Providers Count": len(providers),
            "Exported Providers Count": sum(1 for p in providers if is_exported(p))
        })

        return True

    except Exception as e:
        print(f"[!] Failed to parse {app_name}: {e}")
        return False

# ==============================
# MAIN LOGIC
# ==============================
data = []
parsed_count = 0

os.makedirs(TMP_DECODE_DIR, exist_ok=True)

manifest_files = [
    f for f in os.listdir(MANIFEST_DIR)
    if f.lower().endswith("manifest.xml")
]

# --------------------------------
# CASE 1: Manifest XMLs already exist
# --------------------------------
if manifest_files:
    print("[*] Manifest files found. Parsing directly...")

    for filename in manifest_files:
        path = os.path.join(MANIFEST_DIR, filename)
        app_name = filename.replace("_manifest.xml", "")
        if parse_manifest(path, app_name, data):
            parsed_count += 1

# --------------------------------
# CASE 2: No manifests → fallback to APKs
# --------------------------------
else:
    print("[*] No manifest XML found. Falling back to APK decompilation...")

    if not os.path.isdir(APK_DIR):
        print("[-] APK folder not found.")
        exit(1)

    for apk in os.listdir(APK_DIR):
        if not apk.lower().endswith(".apk"):
            continue

        apk_path = os.path.join(APK_DIR, apk)
        out_dir = os.path.join(TMP_DECODE_DIR, apk)

        if decode_apk(apk_path, out_dir):
            manifest_path = os.path.join(out_dir, "AndroidManifest.xml")
            if os.path.exists(manifest_path):
                if parse_manifest(manifest_path, apk.replace(".apk", ""), data):
                    parsed_count += 1
            else:
                print(f"[!] Manifest not found for {apk}")

        shutil.rmtree(out_dir, ignore_errors=True)

# ==============================
# SAVE OUTPUT
# ==============================
if data:
    df = pd.DataFrame(data)
    output_file = os.path.join(MANIFEST_DIR, "App_Metadata_Counts.xlsx")
    df.to_excel(output_file, index=False)

    print(f"[+] Parsed {parsed_count} apps")
    print(f"[+] Excel saved → {output_file}")
else:
    print("[-] No data extracted.")
