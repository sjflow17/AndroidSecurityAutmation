# 🚀 Android Security Automation

A collection of automation tools for **Android Application Security Testing (VAPT)**, focusing on:

* APK reverse engineering
* Firebase misconfiguration detection
* Hardcoded secret discovery
* Native library analysis
* Google Cloud / AppSpot enumeration

---

## 🔥 Features

### 📱 APK Analysis

* Extract `strings.xml` from APKs
* Detect hardcoded secrets, API keys, JWTs
* Extract metadata from AndroidManifest
* Identify exposed components

---

### ☁️ Firebase Security Testing

* Detect Firebase database URLs from APKs
* Automated misconfiguration scanning
* Bulk pipeline for testing multiple apps

---

### 🌐 Cloud & Backend Discovery

* AppSpot endpoint enumeration
* GCS bucket detection and exposure testing
* Sensitive endpoint discovery

---

### 🧬 Native Code Analysis

* JNI attack surface mapping
* Unsafe native function detection
* Secret extraction from `.so` binaries
* Readelf-based deep inspection

---

## 🛠️ Installation

```bash
git clone https://github.com/your-username/Android-AppSec-Toolkit.git
cd Android-AppSec-Toolkit
pip install -r requirements.txt
```

---

## ⚙️ Requirements

* Python 3.x
* apktool
* aapt
* readelf
* strings (GNU binutils)
* gsutil (optional for GCS checks)

---

## 🚀 Usage

### 1. Extract strings from APK

```bash
python Extract_Strings_from_apk.py
```

### 2. Run Firebase pipeline

```bash
python Firebase_pipeline.py
```

### 3. Scan Firebase manually

```bash
python Firebasechecks.py
```

### 4. Scan hardcoded secrets

```bash
python Hardcoded Strings Scanner.py
```

### 5. Native attack surface mapping

```bash
python Native attack surface mapper.py
```

---

## ⚠️ Disclaimer

This toolkit is intended for:

* Educational purposes
* Authorized security testing only

Do not use against systems without proper permission.

---

## 👨‍💻 Author

Security Researcher | VAPT | Bug Bounty Hunter
