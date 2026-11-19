# Praktikum Keamanan Siber: Membangun Password Manager CLI

**Level:** Pemula–Menengah | **Durasi:** 4 sesi × 90 menit (atau 2–3 minggu mandiri)
**Bahasa:** Python 3.9+ | **Library:** `cryptography`

---

## 1. Skenario

Kamu adalah engineer keamanan di sebuah startup kecil. Tim sering menyimpan password server dan akun layanan di file `passwords.txt` atau catatan chat. Setelah satu laptop anggota tim hilang, manajemen meminta solusi sederhana: **password manager berbasis command line** yang menyimpan semua kredensial dalam satu file terenkripsi, bisa dibuka hanya dengan master password, dan terdeteksi jika file diubah orang lain.

Tugasmu: membangun prototipenya, mengujinya, lalu menganalisis kelemahannya seperti seorang auditor.

## 2. Tujuan Pembelajaran

Setelah praktikum, kamu mampu:

1. Menjelaskan perbedaan **hashing**, **enkripsi simetris**, dan **KDF**.
2. Menurunkan kunci kriptografi dari password memakai **Scrypt** dan **salt**.
3. Mengenkripsi data dengan **AES-256-GCM** dan menjelaskan peran **nonce** serta **authentication tag**.
4. Mengamankan file (izin 600, penulisan atomik) dan input rahasia (`getpass`).
5. Menghasilkan password acak dengan **CSPRNG** (`secrets`).
6. Menulis unit test untuk properti keamanan, bukan hanya fungsi.
7. Mengidentifikasi ancaman dan batasan desain (threat modeling dasar).

## 3. Prasyarat dan Persiapan

```bash
python3 --version              # minimal 3.9
python3 -m venv .venv && source .venv/bin/activate
pip install cryptography
```

Struktur proyek:

```
praktikum/
├── pm.py          # program utama
├── test_pm.py     # unit test
└── README.md
```

> **Aturan etika:** gunakan hanya data dummy. Jangan menyimpan password asli di vault praktikum, dan jangan menjalankan percobaan serangan di luar mesin sendiri.

## 4. Konsep Inti (baca sebelum mulai)

| Konsep | Penjelasan singkat | Dipakai untuk |
|---|---|---|
| **Hash** (SHA-256) | Satu arah, cepat, tanpa kunci | Cek integritas, bukan menyimpan password |
| **KDF** (Scrypt) | Hash sengaja *lambat dan boros memori* | Mengubah master password jadi kunci 256-bit |
| **Salt** | Nilai acak publik, unik per vault | Mencegah rainbow table dan serangan massal |
| **AES-256-GCM** | Enkripsi simetris + autentikasi (AEAD) | Merahasiakan dan melindungi keaslian vault |
| **Nonce** | 12 byte unik per enkripsi | Pemakaian ulang nonce dengan kunci sama = fatal |
| **Tag GCM** | 16 byte penanda keaslian | Mendeteksi password salah atau file dimodifikasi |
| **CSPRNG** | Generator acak aman (`os.urandom`, `secrets`) | Salt, nonce, password acak (jangan pakai `random`) |

Alur enkripsi:

```
master password + salt ──Scrypt──► kunci 256-bit
vault (JSON) + kunci + nonce ──AES-GCM──► ciphertext + tag
file = MAGIC | VERSION | SALT | NONCE | CIPHERTEXT+TAG
```

## 5. Tahapan Praktikum

### Sesi 1: Fondasi Kriptografi (90 menit)

**Latihan 1.1 (eksplorasi hash).** Di Python interaktif, hitung `hashlib.sha256(b"password").hexdigest()` dan `...(b"Password")`. Catat: apa yang terjadi bila satu huruf berubah (avalanche effect)?

**Latihan 1.2 (kenapa hash biasa tidak cukup).** Ukur waktu `sha256` vs `Scrypt` untuk 1000 percobaan password. Hitung perkiraan berapa tebakan per detik yang bisa dilakukan penyerang pada masing-masing.

**Latihan 1.3 (derive key).** Implementasikan `derive_key(master_password, salt)` dengan Scrypt (`n=2**15, r=8, p=1, length=32`). Verifikasi: salt sama + password sama → kunci sama; salt berbeda → kunci berbeda.

**Pertanyaan refleksi:** Mengapa salt boleh disimpan tanpa dienkripsi di dalam file?

### Sesi 2: Enkripsi dan Format Vault (90 menit)

**Latihan 2.1.** Implementasikan `encrypt_vault` dan `decrypt_vault` dengan `AESGCM`. Format file: `MAGIC | VERSION | SALT | NONCE | CIPHERTEXT+TAG`.

**Latihan 2.2 (AAD).** Sertakan header (`MAGIC + VERSION`) sebagai *associated data*. Ubah satu byte pada header dan buktikan dekripsi gagal.

**Latihan 2.3 (eksperimen sengaja salah).** Di skrip terpisah (bukan di `pm.py`), enkripsi dua pesan berbeda dengan **kunci dan nonce yang sama**, lalu XOR kedua ciphertext. Amati bahwa hasilnya membocorkan XOR kedua plaintext. Ini alasan nonce wajib baru setiap kali menyimpan.

**Pertanyaan refleksi:** Apa bedanya AES-CBC dengan AES-GCM dari sisi deteksi modifikasi?

### Sesi 3: CLI, Penyimpanan Aman, dan Generator (90 menit)

**Latihan 3.1.** Bangun perintah `init`, `add`, `get`, `list`, `delete` dengan `argparse`.

**Latihan 3.2 (input aman).** Gunakan `getpass.getpass()`. Jelaskan mengapa master password tidak boleh diterima sebagai argumen (`--password xxx`). Petunjuk: riwayat shell dan daftar proses (`ps`).

**Latihan 3.3 (file aman).** Simpan vault dengan izin `0o600` dan tulis secara **atomik** (tulis ke `.tmp`, lalu `os.replace`). Apa yang terjadi pada vault jika program crash saat menulis tanpa langkah ini?

**Latihan 3.4 (generator).** Buat `generate_password()` dengan `secrets.choice`, wajibkan huruf besar, kecil, dan angka. Hitung entropinya: `panjang × log2(ukuran_alfabet)`.

### Sesi 4: Pengujian, Serangan, dan Laporan (90 menit)

**Latihan 4.1.** Jalankan `python3 -m unittest -v test_pm.py`. Semua tes harus lulus. Tambahkan **minimal 3 tes baru** milikmu sendiri (lihat bagian 7).

**Latihan 4.2 (serangan brute force, di vault dummy milikmu).** Buat vault dengan master password 6 huruf kecil. Tulis skrip yang mencoba semua kombinasi dan ukur waktu per tebakan. Ekstrapolasi: berapa lama untuk 12 karakter acak? Simpulkan nilai KDF yang lambat.

**Latihan 4.3 (tamper test).** Ubah satu bit di mana saja pada file vault (hex editor atau skrip). Buktikan program menolak membuka dan memberi pesan yang tepat.

**Latihan 4.4 (laporan).** Isi tabel threat model (bagian 6) dan tulis laporan 1–2 halaman.

## 6. Threat Model (lengkapi sebagai tugas)

| Ancaman | Apakah dilindungi? | Mekanisme / alasan |
|---|---|---|
| Laptop hilang, file vault dicuri | ? | |
| Penyerang menebak master password offline | ? | |
| Penyerang mengubah isi file vault | ? | |
| Malware keylogger di komputer | ? | |
| Orang lain membaca layar saat `get` dijalankan | ? | |
| Password terbaca di memori / swap | ? | |
| Lupa master password | ? | |

Contoh jawaban baris pertama: *Ya, selama master password kuat. Data terenkripsi AES-256-GCM, kunci diturunkan dengan Scrypt.*

## 7. Tugas Pengembangan (pilih minimal 2)

- **Mudah:** perintah `change-master` untuk mengganti master password (dekripsi lalu enkripsi ulang dengan salt baru).
- **Mudah:** perintah `search <kata>` pada nama entri.
- **Sedang:** hapus password dari clipboard otomatis setelah 20 detik (`pyperclip` + `threading.Timer`).
- **Sedang:** batasi percobaan: tunda 2 detik, 4 detik, dst. setelah tiap kegagalan.
- **Sedang:** cek password terhadap daftar bocor secara **offline** (file daftar password umum).
- **Lanjutan:** simpan parameter Scrypt (`n, r, p`) di header agar bisa dinaikkan tanpa merusak vault lama.
- **Lanjutan:** dukung *key file* sebagai faktor kedua selain master password.
- **Lanjutan:** ekspor/impor CSV terenkripsi dengan peringatan keamanan.

## 8. Rubrik Penilaian (100 poin)

| Komponen | Poin | Kriteria |
|---|---|---|
| Kriptografi benar | 30 | Scrypt + salt, AES-GCM, nonce baru tiap simpan, AAD |
| Fungsi CLI | 15 | init/add/get/list/delete berjalan, error ditangani |
| Praktik aman | 15 | getpass, izin 600, atomic write, tanpa log rahasia |
| Pengujian | 15 | Semua tes lulus + 3 tes tambahan bermakna |
| Eksperimen serangan | 10 | Brute force terukur, tamper test terbukti |
| Threat model & laporan | 10 | Analisis jujur termasuk keterbatasan |
| Pengembangan tambahan | 5 | Minimal 2 fitur dari bagian 7 |

## 9. Pertanyaan Diskusi / Ujian Lisan

1. Mengapa Scrypt/Argon2/bcrypt lebih tepat daripada SHA-256 untuk menurunkan kunci dari password?
2. Apa yang terjadi jika dua vault memakai salt yang sama?
3. Mengapa pesan error "password salah atau file dimodifikasi" digabung, tidak dipisah?
4. Sebutkan dua hal yang **tidak** bisa dilindungi password manager ini.
5. Jika vault disimpan di cloud, apa yang masih aman dan apa yang bocor (metadata)?
6. Apa risiko menyimpan seluruh vault dalam satu blob terenkripsi dibanding mengenkripsi per entri?

## 10. Keterbatasan Kode Referensi (jujur dan penting)

Proyek ini untuk **belajar**, bukan menggantikan KeePassXC atau Bitwarden.

- Password muncul sebagai teks biasa di layar dan di memori Python; string Python tidak bisa dihapus dengan andal.
- Tidak ada perlindungan terhadap keylogger atau malware.
- Seluruh vault didekripsi sekaligus saat dibuka.
- Tidak ada pembatasan percobaan; keamanan bergantung pada kekuatan master password dan biaya Scrypt.
- Parameter Scrypt tetap di kode (lihat tugas pengembangan lanjutan).

## 11. Referensi

- Dokumentasi `cryptography` (AEAD & Scrypt): cryptography.io
- OWASP Password Storage Cheat Sheet
- OWASP Cryptographic Storage Cheat Sheet
- NIST SP 800-63B (panduan password)

## 12. Kunci Jawaban Singkat (untuk pengajar)

- **Salt publik:** tujuannya keunikan, bukan kerahasiaan; penyerang tetap harus memecah tiap vault satu per satu.
- **Nonce reuse:** pada GCM/CTR, `C1 ⊕ C2 = P1 ⊕ P2`, sehingga plaintext bocor dan kunci autentikasi bisa dipulihkan.
- **CBC vs GCM:** CBC tidak mengautentikasi, bit-flipping tak terdeteksi; GCM memberi tag.
- **Error digabung:** agar tidak menjadi oracle yang membedakan "password salah" dari "file rusak".
- **Tidak terlindungi:** keylogger/malware, dan tebakan password lemah.
