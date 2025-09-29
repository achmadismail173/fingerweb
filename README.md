# 🕵️ FingerWeb — Web Tech Detective CLI (v1.0)

FingerWeb adalah *Command Line Interface (CLI)* yang cepat dan akurat untuk deteksi teknologi web (CMS, Framework, Infrastructure, dan JS Front-end) pada sebuah target URL. Tool ini dirancang untuk memberikan *output* yang bersih, ringkas, dan sangat informatif.

✨ **Clean Output | Powered by x1n73ct**

---

## 🚀 Fitur Utama

* **Deteksi Teknologi Multi-Layer:** Mengidentifikasi CMS, *Backend Framework* (e.g., Laravel, Django, WordPress), dan *JavaScript Framework* (e.g., React, Vue, Angular) beserta versinya.
* **Output Paling Bersih:** Hanya menampilkan satu teknologi utama (skor tertinggi) untuk CMS/Framework, dan menampilkan semua JS Framework yang terdeteksi.
* **Analisis Infrastruktur:** Mendeteksi *proxy* atau layanan infrastruktur populer (e.g., Cloudflare, Akamai, Varnish).
* **Deteksi CI/CD Tersembunyi:** Menggunakan teknik *custom 404 baseline* untuk mengidentifikasi keberadaan *file/folder* CI/CD (e.g., `.github/workflows`, `.gitlab-ci.yml`).
* **Analisis Keamanan:** Memeriksa status *Security Headers* (CSP, XFO, HSTS) dan informasi sertifikat TLS/SSL.
* **Favicon Hashing:** Menggunakan *hash* `mmh3` untuk mengidentifikasi teknologi melalui ikon mereka.

---

## ⚙️ Instalasi

FingerWeb dibuat menggunakan **Python 3**. Pastikan Anda telah menginstal semua dependensi yang diperlukan.

### 1. Kloning Repositori

```bash
# Ganti <username-anda> dengan nama pengguna GitHub Anda
git clone https://github.com/achmadismail173/fingerweb.git
cd fingerweb
```
### 2. Instal Dependensi
```bash
pip install -r requirements.txt
```

---

## 💡 Penggunaan

Pemindaian Tunggal

Gunakan opsi -u (atau --url) untuk memindai target tunggal.

```bash
python3 dev.py -u https://www.contoh-target.com
```

Contoh Tampilan (Output CLI)

```bash
╔══════════════════════════════════════════════════════════════╗
║   🕵️ FingerWeb — Web Tech Detective CLI (v2.3)               ║
║   ✨ Clean Output | Powered by x1n73ct                       ║
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


Pemindaian Massal dan Output JSON

```bash
# Memindai daftar URL dari file 'targets.txt' dan menyimpan hasilnya ke 'results.json'
python3 dev.py -l targets.txt -o results.json --json --threads 5
```

## ⚙️ Command Line Interface (CLI) Options

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
