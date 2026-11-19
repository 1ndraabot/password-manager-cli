"""
Pada latihan ini melakukan perbandingan hash cepat dengan KDF lambat. Dalam pengukuran waktu akan menggunakan lib time untuk mengukur keakuratan dari hasil.
"""

import hashlib, time
from hashlib import scrypt
import os

N = 1000
password = b"password123"
salt = os.urandom(16)

start = time.perf_counter()
for _ in range(N):
    hashlib.sha256(password).hexdigest()
sha_time = time.perf_counter() - start

start = time.perf_counter()
for _ in range(N):
    scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32)
scrypt_time = time.perf_counter() - start

print("SHA256 total:", sha_time)
print("Scrypt total:", scrypt_time)
print("SHA256/tebakan:", sha_time / N)
print("Scrypt/tebakan:", scrypt_time / N)
print("Tebakan/detik SHA256:", N / sha_time)
print("Tebakan/detik Scrypt:", N / scrypt_time)


"""
Hasilnya dapat terlihat ketika seseorang menggunakan brute-forcing dalam penebakan password, SHA-256 dapat menebak 1000 password dalam 1,12 detik, sedangkan Scrypt membutuhkan waktu 73836~ detik untuk menebak 1000 password.
Dalam dunia nyata, alasan Password Manager menggunakan KDF lambat seperti Scrypt adalah mitigasi dalam mengamankan data. Jadi, sekalipun server jebol maka hacker membutuhkan waktu 20,5 jam untuk menebak password. Hal ini dapat memberikan waktu defense team untuk menanggulangi kejadian tersebut.
"""