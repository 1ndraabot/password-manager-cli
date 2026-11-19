# Tujuan praktikum ini adalah memahami AES-GCM dengan mengimplementasikannya

import os
import json
from hashlib import scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"PMV1"
VERSION = b"\x01"
SALT_LEN = 16
NONCE_LEN = 12

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15,8,1
DKLEN = 32

def derive_key(master_password: str, salt: bytes):
    return scrypt(
        master_password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        maxmem=64*1024*1024,
        dklen=DKLEN
    )

def encrypt_vault(master_password: str, plaintext_dict: dict) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(master_password, salt)

    header = MAGIC + VERSION + salt
    aad = header

    plaintext = json.dumps(plaintext_dict, ensure_ascii=False).encode("utf-8")
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, aad)
    return header + nonce + ct_and_tag

def decrypt_vault(master_password: str, file_bytes: bytes) -> dict:
    min_len = len(MAGIC) + len(VERSION) + SALT_LEN + NONCE_LEN + 16
    if len(file_bytes) < min_len:
        raise ValueError("[!] File vault tidak valid: terlalu pendek.")

    magic = file_bytes[:4]
    version = file_bytes[4:5]
    if magic != MAGIC:
        raise ValueError(f"[!] File vault tidak valid: MAGIC={magic!r}.")
    if version != VERSION:
        raise ValueError(f"[!] File vault tidak didukung: MAGIC={version!r}.")

    off = 5
    salt = file_bytes[off:off + SALT_LEN]; off += SALT_LEN
    nonce = file_bytes[off:off + NONCE_LEN]; off += NONCE_LEN
    ct_and_tag = file_bytes[off:]

    aad = MAGIC + VERSION + salt
    key = derive_key(master_password, salt)

    try:
        plaintext = AESGCM(key).decrypt(nonce, ct_and_tag, aad)
    except Exception:
        raise ValueError(
            "Gagal mendekripsi vault: master password salah "
            "atau file telah dimodifikasi."
        )

    return json.loads(plaintext.decode("utf-8"))

def main():
    password = "password123A"
    data = {
        "notes": "vault uji coba",
        "items": [
            {"site": "example.com", "user": "alice", "pass": "s3cr3t!"},
            {"site": "mail.test", "user": "bob", "pass": "hunter"}
        ]
    }

    print("= = = ENKRIPSI = = =")
    blob = encrypt_vault(password, data)
    print(f"Panjang file: {len(blob)} byte (header {5+SALT_LEN+NONCE_LEN}, "
          f"cipher+tag {len(blob)-5-SALT_LEN-NONCE_LEN})")
    with open("vault.pmv1", "wb") as f:
        f.write(blob)

    print("\n = = = DEKRIPSI PASSWORD BENAR = = =")
    with open("vault.pmv1", "rb") as f:
        blob2 = f.read()
    hasil = decrypt_vault(password, blob2)
    print("Isi vault:", hasil)
    assert hasil == data, "Dekripsi tidak mengembalikan data semula"

    print("\n = = = DEKRIPSI PASSWORD SALAH = = =")
    try:
        decrypt_vault("passwordSalah", blob2)
        print("BUG: seharusnya gagal!")
    except ValueError as e:
        print("Gagal sebagaimana mestinya:", e)

    print("\n = = = FILE DIMODIFIKASI 1 BYTE = = =")
    tampered = bytearray(blob2)
    tampered[-1] ^= 0x01
    try:
        decrypt_vault(password, bytes(tampered))
        print("BUG: seharusnya gagal!")
    except ValueError as e:
        print("Gagal sebagaimana mestinya:", e)

if __name__ == "__main__":
    main()
    
"""
Dari hasil praktikum mendapati beberapa hasil sebagai berikut.
[*] Implementasi encrypt_vault(master_password, plaintext_dict) -> bytes
Fungsi enkripsi mengamankan dict plaintext menggunakan alur, key derivation membangun salt kripto (16 bytes) dengan os.urandom lalu menurunkan kunci simetris 256-bit menggunakan scrypt dengan para meter n = 2^15, r = 8, dan p = 1, serta batas memori 64 MiB.
Selanjutnya serialisasi dengan mengonversi plaintext_dict menjadi byte JSON dengan format UTF-8. Lalu, AEAD mambangun nonce (12 byte) dan melakukan enkripsi menggunakan nonce, plaintext, dan aad.
Format dari binary outputnya adalah MAGIC + VERSION + SALT + NONCE + CIPHERTEXT + TAG

[*] Implementasi decrypt_vault(master_password, file_bytes) -> dict
Fungsi dekripsi ini adalah memvalidasi dan memulihkan data. Pada validasi header akan memastikan panjang data >= 49 byte dan memeriksa apakah magic == b"PMV1" dan version == b"\x01".
Dilanjut dengan parsing struktur data dengan memisahkan salt, nonce, dan ciphertext + auth_tag.
Terdapat juga derivasi kunci dan otentikasi GCM dengan menurunkan kunci menggunakan master_password dan salt, serta menggunakan AESGCM.decrypt untuk mendekripsi dan memverifikasi integritas aad.
Terakhir deserialisasi dengan memparsing string JSON hasil dekripsi menjadi struktur dict python.

[*] Hasil pengujian general
Hasilnya, data berhasil dienkripsi menjadi file biner dengan nama "vault.pmv1" berukuran 204 byte, kemudian dibaca dan didekripsi kembali.

[*] Hasil pengujian penanganan password salah dan tampering
Analisis: AES-GCM bersifat Authenticated Encryption. Jika kunci salah (karena password salah) atau ada 1 bit data yang diubah (tampering), verifikasi Authentication Tag (16 byte) akan gagal dan memicu exception kriptografi. Script menangkapnya dan mengeluarkan pesan error yang aman, jelas, dan seragam.

Special question: "Mengapa Nonce Tidak Boleh Dirahasiakan, Tetapi Tidak Boleh Dipakai Ulang?"
Alasan kenapa tidak dirahasiakan ialah karena nonce bukanlah sebuah kunci rahasia melainkan hanya sebuah komponen diversifikasi. Penyerang tidak mendapat keuntungan apapun jika mendapatkan nilai nonce. Namun, bagi pihak yang mendekripsi wajib mengetahui nonce untuk merekonstruksi keystream counter pada proses dekripsi.
Alasan mutlak tidak boleh digunakan ulang ialah Kerentanan Kerahasiaan (Two-Time Pad). Jika kunci yang sama (K) dan nonce yang sama (N) mengenkripsi dua plaintext berbeda (P1 dan P2) keystream yang dihasilkan identik (S).Penyerang dapat melakukan operasi XOR pada kedua ciphertext. Kondisi ini membatalkan proteksi enkripsi dan membuka celah pembacaan data asli secara langsung.
"""