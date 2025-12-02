from pure_des import DES

plaintext = """
Kawan
Di saat suka, kau ada,
Di saat duka, kau tak hilang.
Persahabatan kita takkan sirna, Terjalin erat, selalu menantang.
Bersama kita lalui badai,
Bersama kita meraih mimpi.
Kau teman, bukan sekadar ramai,
Terima kasih, kawan sejati
"""

key = "133457799BBCDFF1"

# buat objek DES
des = DES(key)

# enkripsi
cipher = des.encrypt(plaintext)

print("Ciphertext (hex):")
print(cipher.hex())
