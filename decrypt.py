from pure_des import DES

key = "133457799BBCDFF1"

# Baca ciphertext hex dari file
with open("ciphertext.hex", "r") as f:
    hex_data = f.read().strip()

# Convert hex ke bytes
cipher_bytes = bytes.fromhex(hex_data)

# Buat objek DES
des = DES(key)

# Dekripsi
plaintext = des.decrypt(cipher_bytes)

print("Plaintext hasil dekripsi:")
print(plaintext)