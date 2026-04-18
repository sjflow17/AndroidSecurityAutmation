import os
import re
import subprocess
import csv
from datetime import datetime

# ================= CONFIG =================
STRINGS_DIR = "strings"
CHECKER_SCRIPT = "Firebasechecks.py"

OUTPUT_DIR = "results"
RAW_OUTPUT = os.path.join(OUTPUT_DIR, "firebase_raw.txt")
CSV_OUTPUT = os.path.join(OUTPUT_DIR, "firebase_results.csv")

FIREBASE_REGEX = re.compile(
    r"https://[a-zA-Z0-9._\-]+\.firebaseio\.com|"
    r"https://[a-zA-Z0-9._\-]+\.firebasedatabase\.app"
)

# =========================================

os.makedirs(OUTPUT_DIR, exist_ok=True)


def extract_buckets_with_sources():
    """
    Returns:
      {
        firebase_url: { "source1 Strings.xml", "source2 Strings.xml" }
      }
    """
    bucket_map = {}

    print("[*] Scanning strings.xml files...\n")

    for filename in os.listdir(STRINGS_DIR):
        if not filename.lower().endswith(".xml"):
            continue

        path = os.path.join(STRINGS_DIR, filename)
        print(f"[+] Reading {filename}")

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            matches = FIREBASE_REGEX.findall(content)

            for match in matches:
                bucket = match.rstrip("/")
                bucket_map.setdefault(bucket, set()).add(filename)

    return bucket_map


def run_firebase_checker(bucket):
    """
    Runs Firebasechecks.py interactively
    Returns full output lines
    """
    print(f"\n[>] Running Firebase checks on: {bucket}\n")

    process = subprocess.Popen(
        ["python", CHECKER_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    collected_output = []

    # send bucket to Firebasechecks.py
    process.stdin.write(bucket + "\n")
    process.stdin.flush()

    for line in process.stdout:
        print(line, end="")           # realtime output
        collected_output.append(line)

    process.wait()
    return collected_output


def parse_results(bucket, output_lines):
    """
    Parses Firebasechecks.py output
    """
    parsed = []

    for line in output_lines:
        line = line.strip()

        if line.startswith("[+] OPEN"):
            parsed.append((bucket, "OPEN", line))
        elif line.startswith("[-] DENIED"):
            parsed.append((bucket, "DENIED", line))
        elif line.startswith("[!]"):
            parsed.append((bucket, "ERROR", line))

    return parsed


def main():
    bucket_map = extract_buckets_with_sources()

    if not bucket_map:
        print("\n[-] No Firebase databases found.")
        return

    print(f"\n[*] Found {len(bucket_map)} unique Firebase databases\n")

    with open(RAW_OUTPUT, "w", encoding="utf-8") as raw_file, \
         open(CSV_OUTPUT, "w", newline="", encoding="utf-8") as csv_file:

        writer = csv.writer(csv_file)
        writer.writerow([
            "Timestamp (UTC)",
            "Firebase Database",
            "Source strings.xml",
            "Status",
            "Detail"
        ])

        for bucket, sources in bucket_map.items():
            source_str = ", ".join(sorted(sources))

            print(f"\n[=] Database: {bucket}")
            print(f"[=] Source(s): {source_str}")

            raw_file.write(f"\n==== {bucket} ====\n")
            raw_file.write(f"Sources: {source_str}\n\n")

            output = run_firebase_checker(bucket)
            raw_file.writelines(output)

            parsed = parse_results(bucket, output)

            for _, status, detail in parsed:
                writer.writerow([
                    datetime.utcnow().isoformat(),
                    bucket,
                    source_str,
                    status,
                    detail
                ])

    print("\n[✓] Pipeline completed successfully")
    print(f"[+] Raw log : {RAW_OUTPUT}")
    print(f"[+] CSV     : {CSV_OUTPUT}")


if __name__ == "__main__":
    main()
