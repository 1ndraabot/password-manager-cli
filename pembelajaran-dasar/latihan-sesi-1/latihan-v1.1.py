"""
Tujuan dari pembelajaran praktikum ini ialah memahami avalanche effect pada hash. 
Avalanche effect adalah sifat ideal dari fungsi hash kriptografis dimana perubahan kecil pada input dapat menyebabkan perubahan besar dan tidak terduga pada output hash
"""

import hashlib

print("Hash 'password'")
print(hashlib.sha256(b"password").hexdigest())
print("\n Hash 'Password'")
print(hashlib.sha256(b"Password").hexdigest())
print("\n Hash 'passworD'")
print(hashlib.sha256(b"passworD").hexdigest())

"""
Pada hasil ini terlihat jika hasil ketiganya berbeda sangat jauh meskipun pada string awalnya hanya berbeda pada kapitalisasi huruf awal dan akhir.
"""
