#!/usr/bin/env python3

import os
import re
import hashlib
import subprocess
import requests
import shutil
from collections import defaultdict
from datetime import datetime

# =========================
# Configuration
# =========================

INPUT_DIR = "Strings"
OUTPUT_DIR = "appspot_results"
TIMEOUT = 10

os.makedirs(OUTPUT_DIR, exist_ok=True)

# =========================
# Regex patterns (Android-aware)
# =========================

PATTERNS = [
    r"https?://[a-zA-Z0-9.-]+\.appspot\.com",
    r"https?://storage\.googleapis\.com/[a-zA-Z0-9._/-]+",
    r"https?://[a-zA-Z0-9.-]+\.storage\.googleapis\.com",

    # Android-style (no scheme)
    r"[a-zA-Z0-9.-]+\.appspot\.com",
    r"storage\.googleapis\.com/[a-zA-Z0-9._/-]+",
    r"[a-zA-Z0-9.-]+\.storage\.googleapis\.com",
]

# =========================
# Endpoint groups
# =========================

COMMON_ENDPOINTS = [
    "/health", "/healthz", "/status", "/statusz",
    "/ready", "/readiness", "/liveness", "/live",
    "/ping", "/version", "/build", "/info", "/metadata"
]

TASK_ENDPOINTS = [
    "/_ah/queue", "/_ah/queue/default", "/_ah/queue/deferred",
    "/_ah/cron", "/_ah/cron/jobs", "/_ah/task", "/_ah/tasks"
]

BLOB_ENDPOINTS = [
    "/_ah/blobstore", "/_ah/blobstore/upload", "/_ah/blobstore/reader",
    "/blobstore", "/blobstore/upload",
    "/upload", "/uploads", "/file/upload",
    "/files/upload", "/media/upload"
]

SENSITIVE_FILES = [
    "/.env", "/.git/HEAD", "/.git/config",
    "/config.json", "/env.json",
    "/app.yaml", "/app.yml",
    "/appengine-web.xml", "/web.xml",
    "/credentials.json", "/client_secrets.json"
]

ALL_ENDPOINT_GROUPS = {
    "COMMON": COMMON_ENDPOINTS,
    "TASKS": TASK_ENDPOINTS,
    "BLOBSTORE": BLOB_ENDPOINTS,
    "SENSITIVE": SENSITIVE_FILES,
}

# =========================
# Helpers
# =========================

def sha1(x):
    return hashlib.sha1(x.encode()).hexdigest()

def gsutil_available():
    return shutil.which("gsutil") is not None

def run_cmd(cmd):
    try:
        r = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT,
            text=True
        )
        return r.stdout + r.stderr
    except Exception as e:
        return str(e)

def classify(status, body):
    if isinstance(status, str):
        return status
    if status == 200:
        return "OPEN"
    if status == 401:
        return "AUTH_REQUIRED"
    if status == 403:
        return "FORBIDDEN"
    if status == 404:
        return "NOT_FOUND"
    return f"HTTP_{status}"

def extract_bucket(url):
    if "storage.googleapis.com/" in url:
        return url.split("storage.googleapis.com/")[1].split("/")[0]
    if ".storage.googleapis.com" in url:
        return url.replace("https://", "").split(".storage.googleapis.com")[0]
    return None

# =========================
# STEP 1: Extract targets
# =========================

print("[*] Extracting targets from strings.xml")

targets = set()

for file in os.listdir(INPUT_DIR):
    if not file.lower().endswith(".xml"):
        continue

    path = os.path.join(INPUT_DIR, file)

    try:
        content = open(path, errors="ignore").read()

        # Android XML unescape
        content = content.replace("\\/", "/")

        for pattern in PATTERNS:
            for m in re.findall(pattern, content):
                if not m.startswith("http"):
                    m = "https://" + m
                targets.add(m)

    except Exception as e:
        print(f"[!] Failed to read {file}: {e}")

print(f"[+] Found {len(targets)} base targets")

if not targets:
    print("[-] No targets extracted — check Strings folder")
    exit(0)

# =========================
# STEP 2: Expand App Engine services
# =========================

expanded_targets = set()

for t in targets:
    expanded_targets.add(t)

    if t.endswith(".appspot.com"):
        base = t.replace("https://", "")
        for svc in [
            "default", "v1", "v2", "api", "admin",
            "staging", "dev", "test", "internal"
        ]:
            expanded_targets.add(f"https://{svc}-dot-{base}")

print(f"[+] Expanded to {len(expanded_targets)} total targets")

# =========================
# STEP 3: Scan
# =========================

gsutil_ok = gsutil_available()
if not gsutil_ok:
    print("[!] gsutil not available — GCS checks skipped")

summary = defaultdict(dict)

for target in sorted(expanded_targets):
    print(f"\n[*] Scanning target: {target}")

    report_path = os.path.join(OUTPUT_DIR, f"{sha1(target)}.txt")

    with open(report_path, "w", encoding="utf-8") as r:
        r.write(f"Target: {target}\n")
        r.write(f"Scan Time: {datetime.utcnow()} UTC\n")
        r.write("=" * 60 + "\n")

        # -------------------------
        # AppSpot scanning
        # -------------------------

        if target.endswith(".appspot.com"):
            for group, paths in ALL_ENDPOINT_GROUPS.items():
                r.write(f"\n[{group}]\n")

                for p in paths:
                    url = target + p
                    print(f"    -> Testing {url}")

                    try:
                        res = requests.get(url, timeout=TIMEOUT)
                        body = res.text.lower()

                        if "invalid iap" in body:
                            result = "IAP_PROTECTED"
                        else:
                            result = classify(res.status_code, body)

                    except Exception:
                        result = "ERROR"

                    r.write(f"{p:30} {result}\n")
                    summary[target][p] = result

        # -------------------------
        # GCS scanning
        # -------------------------

        else:
            bucket = extract_bucket(target)
            if bucket and gsutil_ok:
                r.write("\n[GCS]\n")
                print(f"    -> gsutil ls gs://{bucket}")

                out = run_cmd(["gsutil", "ls", f"gs://{bucket}"])
                if "gs://" in out:
                    r.write("LISTING: TRUE\n")
                else:
                    r.write("LISTING: FALSE\n")

# =========================
# STEP 4: Summary
# =========================

summary_path = os.path.join(OUTPUT_DIR, "summary.txt")

with open(summary_path, "w", encoding="utf-8") as s:
    s.write("AppSpot / GCS Scan Summary\n")
    s.write("=" * 40 + "\n\n")

    for target, results in summary.items():
        s.write(f"{target}\n")
        for ep, res in results.items():
            s.write(f"  {ep:30} {res}\n")
        s.write("\n")

print("\n[*] Scan completed")
print(f"[*] Results stored in: {OUTPUT_DIR}")
