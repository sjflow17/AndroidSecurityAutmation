OWASP_M2_Methodology
-
------------------------------------------------
REQUIREMENTS
------------------------------------------------

- Python 3.x
- apktool available in PATH
  (Windows: apktool.bat)
- readelf available in PATH
- Internet connection (only required for Debug Endpoint Enumeration)


------------------------------------------------
RECOMMENDED FOLDER STRUCTURE
------------------------------------------------

project-folder/
|
|-- APK/
|   |-- app1.apk
|   |-- app2.apk
|
|-- Debug Endpoint Enumeration.py
|-- Manifest SDK Permission Enumeration.py
|-- Native Code Obfuscation.py
|-- Native SDK enumeration.py
|
|-- README.txt


================================================
1) NATIVE SDK ENUMERATION
================================================

Script:
Native SDK enumeration.py

Purpose:
- Scans native libraries (.so files)
- Identifies third-party SDKs embedded at the native layer
- Uses readelf to extract native strings
- Maps SDK presence for OWASP M2 Step 1

What it finds:
- Analytics SDKs (Firebase, Mixpanel, Amplitude)
- Attribution SDKs (Adjust, AppsFlyer)
- Crash SDKs (Sentry, Crashlytics)
- Cloud SDK indicators (AWS, GCP, Azure)

How to run:
python "Native SDK enumeration.py"

Menu options:
1) Scan single APK
2) Scan all APKs in APK folder
3) Scan folder recursively for .so files
4) Scan folder containing multiple APKs

Output file:
native_third_party_sdks.txt


================================================
2) DEBUG / CLOUD ENDPOINT ENUMERATION
================================================

Script:
Debug Endpoint Enumeration.py

Purpose:
- Scans decompiled APK files for backend endpoints
- Detects AWS, Firebase, Google APIs, AppSpot
- Identifies debug, staging, and test URLs
- Safely validates endpoints using HEAD requests
- Used for OWASP M2 Step 5

What it does NOT do:
- No brute forcing
- No directory fuzzing
- No endpoint guessing

How to run:
python "Debug Endpoint Enumeration.py"

Menu options:
1) Scan single APK
2) Scan all APKs in APK folder
3) Scan already decompiled folder
4) Scan folder containing multiple APKs

Output file:
debug_cloud_endpoints.txt


================================================
3) MANIFEST SDK PERMISSION ENUMERATION
================================================

Script:
Manifest SDK Permission Enumeration.py

Purpose:
- Extracts permissions from AndroidManifest.xml
- Identifies dangerous permissions
- Correlates permissions with SDK categories
- Flags permission overreach
- Used for OWASP M2 Step 3

Examples of findings:
- Analytics SDK + Location access
- Ads SDK + Phone state access
- Excessive permissions requiring review

How to run:
python "Manifest SDK Permission Enumeration.py"

Behavior:
- Automatically scans all APKs in the APK folder
- Very fast (manifest-only analysis)

Output file:
m2_step3_permission_analysis.txt


================================================
4) NATIVE CODE OBFUSCATION & TRUST ANALYSIS
================================================

Script:
Native Code Obfuscation.py

Purpose:
- Reviews code integrity and trustworthiness
- Flags:
  - Native libraries (.so)
  - JNI usage
  - Networking symbols in native code
  - Dynamic code loading (DexClassLoader)
  - Reflection usage
  - Crypto usage
- Used for OWASP M2 Step 4

Important:
- This script does NOT claim malware
- It only reports risk indicators
- Manual review is required for confirmation

How to run:
python "Native Code Obfuscation.py"

Menu options:
1) Scan single APK
2) Scan all APKs in APK folder
3) Scan already decompiled folder
4) Scan folder containing multiple APKs

Output file:
m2_step4_code_trust_analysis.txt


================================================
RECOMMENDED USAGE ORDER
================================================

1) Identify native third-party SDKs
   Native SDK enumeration.py

2) Detect cloud, debug, and staging endpoints
   Debug Endpoint Enumeration.py

3) Analyze permission overreach
   Manifest SDK Permission Enumeration.py

4) Review code trust and integrity
   Native Code Obfuscation.py


================================================
IMPORTANT NOTES
================================================

- These scripts are designed for:
  - VAPT
  - Bug bounty research
  - Supply-chain security review

- These scripts are NOT:
  - Malware scanners
  - Exploit tools
  - CVE exploit frameworks

- Automation provides triage and evidence.
  Manual validation is required for exploitation.


================================================
SUMMARY
================================================

This toolkit provides:
- Native SDK visibility
- Backend and debug endpoint detection
- Permission risk analysis
- Code integrity and trust signals

Together, these scripts form a complete and practical
OWASP M2 automation pipeline.
