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
des = DES(key)

cipher = des.encrypt(plaintext)
hex_cipher = cipher.hex()

print("Ciphertext (hex):")
print(hex_cipher)
print()

with open("ciphertext.hex", "w") as f:
    f.write(hex_cipher)

print("Cipher saved to ciphertext.hex")
