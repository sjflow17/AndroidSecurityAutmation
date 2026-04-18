import requests
import json
import time

ENDPOINTS = [
    ".json",
    ".settings/rules.json",
    "rules.json",
    "config.json",
    "settings.json",
    "metadata.json",
    "debug.json",
    "users.json",
    "user.json",
    "accounts.json",
    "auth.json",
    "authentication.json",
    "tokens.json",
    "otp.json",
    "2fa.json",
    "keys.json",
    "api_keys.json",
    "admins.json",
    "staff.json",
    "permissions.json",
    "secrets.json",
    "internal.json",
    "db_creds.json",
    "orders.json",
    "payments.json",
    "purchases.json",
    "activity.json",
    "logs.json",
    "events.json",
    "notifications.json",
    "devices.json"
]

HEADERS = {
    "User-Agent": "Firebase-Security-Test/1.0"
}

def normalize_base(url: str) -> str:
    url = url.strip()
    if url.endswith("/"):
        url = url[:-1]
    return url

def test_endpoint(base, path):
    url = f"{base}/{path}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        status = r.status_code

        if status == 200:
            try:
                data = r.json()
                size = len(json.dumps(data))
                print(f"[+] OPEN   | {url} | size={size}")
            except Exception:
                print(f"[!] OPEN   | {url} | non-JSON response")

        elif status in (401, 403):
            print(f"[-] DENIED | {url}")

        else:
            print(f"[?] {status} | {url}")

    except Exception as e:
        print(f"[!] ERROR  | {url} | {e}")

if __name__ == "__main__":
    print("[*] Firebase Realtime DB Security Scanner\n")

    base = input("Enter Firebase base URL (e.g. https://example.firebaseio.com): ").strip()
    base = normalize_base(base)

    if not base.startswith("http"):
        print("[-] Invalid URL. Must start with http:// or https://")
        exit(1)

    print(f"\n[*] Target: {base}\n")

    for ep in ENDPOINTS:
        test_endpoint(base, ep)
        time.sleep(0.4)  # basic rate-limit

    print("\n[*] Scan completed.")