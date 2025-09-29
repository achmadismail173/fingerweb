# 🕵️ FingerWeb — Web Tech Detective CLI (v2.4)

FingerWeb is a fast and accurate **Command Line Interface (CLI)** tool for web technology detection (CMS, Frameworks, Infrastructure, and JS Front-end) on any target URL. This tool is designed to provide clean, concise, and highly informative output.

✨ **Clean Output | Powered by x1n73ct**

---

## 🚀 Key Features

* **Multi-Layer Technology Detection:** Identifies CMS, Backend Frameworks (e.g., Laravel, Django, WordPress), and JavaScript Frameworks (e.g., React, Vue, Angular), along with their detected versions.
* **Cleanest Output:** Displays only the primary technology (highest score) for CMS/Frameworks and lists all detected JS Frameworks.
* **Infrastructure Analysis:** Detects popular proxy or infrastructure services (e.g., Cloudflare, Akamai, Varnish).
* **Hidden CI/CD Detection:** Uses a custom **404 baseline technique** to identify the presence of CI/CD files/folders (e.g., `.github/workflows`, `.gitlab-ci.yml`).
* **Security Analysis:** Checks the status of critical **Security Headers** (CSP, XFO, HSTS, etc.) and provides TLS/SSL certificate information.
* **Favicon Hashing:** Uses the `mmh3` hash to identify technologies via their favicon icon.

---

## ⚙️ Installation

FingerWeb is built using **Python 3**. Ensure you have all the necessary dependencies installed.

### 1. Cloning the Repository

```bash
git clone https://github.com/achmadismail173/fingerweb.git
cd fingerweb
```


### 2. Instal Dependensi

You need to have requests, colorama, mmh3, and urllib3 installed.

```bash
pip install -r requirements.txt
```

---

## 💡 Usage

Single Target Scan

Use the -u (or --url) option to scan a single target. Include optional flags like --tls and --favicon for more detailed results.

```bash
python3 dev.py -u https://www.contoh-target.com
```

CLI Output Example

```bash
╔══════════════════════════════════════════════════════════════╗
║   🕵️ FingerWeb — Web Tech Detective CLI (v2.3)              ║
║   ✨ Clean Output | Powered by x1n73ct                      ║
╚══════════════════════════════════════════════════════════════╝

==========================================================================
🎯 TARGET SCAN: https://www.contoh-target.com
==========================================================================

--- 💻 TECHNOLOGY STACK (Backend/CMS) ------------------------------
[ CMS/Framework ] : WordPress (6.5.4)
[ Server/Powered  ] : LiteSpeed, PHP/8.2.16

--- 👣 DIGITAL FOOTPRINT --------------------------------------------
[ JS Frameworks   ] : Angular (17.2), React
[ Infrastructure  ] : Cloudflare
[ Favicon Hash    ] : 12a34b5c (Match: WordPress)
[ 404 Baseline    ] : 5f6e7d8c... (Len: 4200 bytes)
[ CI/CD           ] : .github/workflows/

--- 🔒 SECURITY INFO ------------------------------------------------
[ Strict-Transport-Security ] : Status: Present
[ Content-Security-Policy ] : Status: Missing
[ X-Frame-Options ] : Status: Present
[ X-Content-Type-Options ] : Status: Present
[ Referrer-Policy ] : Status: Missing
[ TLS Subject CN  ] : https://www.contoh-target.com
[ TLS Issuer CN   ] : Google Trust Services LLC

==========================================================================
```


Bulk Scanning and JSON Output

```bash
# Scan a list of URLs from 'targets.txt', output results in JSON, and use 5 threads
python3 dev.py -l targets.txt -o results.json --json --threads 5
```

---

### ⚙️ Command Line Interface (CLI) Options

| Short Flag | Long Flag | Description |
| :---: | :---: | :--- |
| `-u` | `--url` | **Single target URL** to scan (e.g., `https://example.com`). |
| `-l` | `--list` | File containing a list of target URLs (one URL per line). |
| `-t` | `--timeout` | Connection timeout in seconds (Default: 10). |
| | `--favicon` | Enables **favicon hashing** and database lookup for deeper fingerprinting. |
| | `--fav-db` | Path to the favicon database file (Default: `db_favicon.json`). |
| `--tls` | | Fetches and displays **TLS/SSL certificate** subject and issuer information. |
| | `--json` | Outputs the result exclusively in **JSON format** (suppresses standard CLI output). |
| `-o` | `--output` | Saves the JSON output to a specified file path. |
| | `--threads` | Number of concurrent threads for bulk scanning (used with `-l`). |

### 🤝 Contributing

This project is licensed under the **MIT License**.
