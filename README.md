# 🕵️ FingerWeb — Web Tech Detective CLI (v2.3)

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
git clone [https://github.com/](https://github.com/)<achmadismail173>/FingerWeb.git
cd FingerWeb
