import os
from hashlib import scrypt

def derive_key(master_password: str, salt: bytes) -> bytes:
    return scrypt(
        master_password.encode("utf-8"),
        salt=salt,
        n=2**15,
        r=8,
        p=1,
        maxmem=128 * 2**15 * 8 * 2,
        dklen=32
    )

salt_a = os.urandom(16)
salt_b = os.urandom(16)

print(f"salt_a = {salt_a.hex()}")
print(f"salt_b = {salt_b.hex()}")

def salt_and_pass_is_same():
    sp_a = derive_key("password123", salt_a)
    sp_b = derive_key("password123", salt_a)
    if sp_a == sp_b:
        print(f"[!] Hasil sama. \n[*] sp_a: {sp_a} \n[*] sp_b: {sp_b}")
    else:
        print("[!] Hasil berbeda!")

def salt_is_same_pass_is_different():
    s_a = derive_key("password123", salt_a)
    s_b = derive_key("password789", salt_a)
    if s_a != s_b:
        print(f"\n[!] Hasil berbeda. \n[*] s_a: {s_a} \n[*] s_b: {s_b}")
    else:
        print("\n[!] Hasil sama.")

def salt_is_different_pass_is_same():
    p_a = derive_key("password123", salt_a)
    p_b = derive_key("password123", salt_b)
    if p_a != p_b:
        print(f"\n[!] Hasil berbeda. \n[*] p_a: {p_a} \n[*] p_b: {p_b}")
    else:
        print("\n[!] Hasil sama.")

if __name__ == "__main__":
    salt_and_pass_is_same()
    salt_is_same_pass_is_different()
    salt_is_different_pass_is_same()

"""
Dari hasil praktikum ini mendapati jika:
- Salt yang sama dengan Password yang sama akan menghasilkan output yang sama juga.
- Salt yang sama dengan Password yang berbeda akan menghasilkan output yang berbeda.
- Salt yang berbeda dengan Password yang sama akan menghasilkan output yang berbeda.
Perlu diketahui jika salt tidak perlu disimpan dengan enkripsi karena secara fungsi salt bukan merahasiakan tetapi membedakan. Dalam brute-forcing penebakan tetap mengacu pada master password, sehingga salt tidak memberikan keuntungan apapun kepada penyerang jika dapat mengetahuinya.
"""