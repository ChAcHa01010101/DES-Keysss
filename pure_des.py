# pure_des.py
# Pure-Python DES implementation (ECB and CBC) with PKCS#5/7 padding.
# Note: This is an educational implementation, not optimized for production.

from typing import List
import sys

# -------------------------
# Permutation and S-box tables (standard DES)
# -------------------------
IP = [
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
]

FP = [
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
]

E = [
    32,1,2,3,4,5,
    4,5,6,7,8,9,
    8,9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
]

P = [
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
]

PC1 = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
]

PC2 = [
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
]

LEFT_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

SBOX = [
# S1
[
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]
],
# S2
[
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]
],
# S3
[
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]
],
# S4
[
[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]
],
# S5
[
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]
],
# S6
[
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]
],
# S7
[
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]
],
# S8
[
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
]
]

# -------------------------
# Helper bit/string functions
# -------------------------
def hex_to_bits(hexstr: str) -> List[int]:
    bits = []
    hexstr = hexstr.strip()
    if hexstr.startswith("0x") or hexstr.startswith("0X"):
        hexstr = hexstr[2:]
    for c in hexstr:
        v = int(c, 16)
        for i in range(4):
            bits.append((v >> (3 - i)) & 1)
    return bits

def bits_to_hex(bits: List[int]) -> str:
    assert len(bits) % 4 == 0
    hex_chars = []
    for i in range(0, len(bits), 4):
        v = (bits[i] << 3) | (bits[i+1] << 2) | (bits[i+2] << 1) | bits[i+3]
        hex_chars.append("{:x}".format(v))
    return "".join(hex_chars).upper()

def bytes_to_bits(b: bytes) -> List[int]:
    bits = []
    for byte in b:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits

def bits_to_bytes(bits: List[int]) -> bytes:
    assert len(bits) % 8 == 0
    out = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for j in range(8):
            val = (val << 1) | bits[i+j]
        out.append(val)
    return bytes(out)

def permute(bits: List[int], table: List[int]) -> List[int]:
    return [bits[i-1] for i in table]

def left_rotate(lst: List[int], n: int) -> List[int]:
    return lst[n:] + lst[:n]

# -------------------------
# Key schedule
# -------------------------
def generate_subkeys(key64_bits: List[int]) -> List[List[int]]:
    # Apply PC1 to get 56-bit key
    key56 = permute(key64_bits, PC1)
    C = key56[:28]
    D = key56[28:]
    subkeys = []
    for shift in LEFT_SHIFTS:
        C = left_rotate(C, shift)
        D = left_rotate(D, shift)
        CD = C + D
        subk = permute(CD, PC2)
        subkeys.append(subk)
    return subkeys  # 16 keys, each 48 bits

# -------------------------
# f function
# -------------------------
def s_box_substitution(bits48: List[int]) -> List[int]:
    out = []
    for i in range(8):
        block = bits48[i*6:(i+1)*6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = SBOX[i][row][col]
        for j in range(4):
            out.append((val >> (3-j)) & 1)
    return out

def feistel(R: List[int], subkey48: List[int]) -> List[int]:
    # Expand R from 32->48
    ER = permute(R, E)
    # XOR with subkey
    x = [a ^ b for a,b in zip(ER, subkey48)]
    # S-box substitution to 32 bits
    s_out = s_box_substitution(x)
    # Permutation P
    return permute(s_out, P)

# -------------------------
# Single block encrypt/decrypt (64-bit)
# -------------------------
def des_block_encrypt(block64_bits: List[int], subkeys: List[List[int]]) -> List[int]:
    # Initial permutation
    block = permute(block64_bits, IP)
    L = block[:32]
    R = block[32:]
    # 16 rounds
    for i in range(16):
        f_out = feistel(R, subkeys[i])
        newR = [l ^ f for l,f in zip(L, f_out)]
        L, R = R, newR
    # Preoutput: R + L (note swap)
    preoutput = R + L
    # Final permutation
    return permute(preoutput, FP)

def des_block_decrypt(block64_bits: List[int], subkeys: List[List[int]]) -> List[int]:
    # Decrypt same as encrypt but subkeys reversed
    return des_block_encrypt(block64_bits, list(reversed(subkeys)))

# -------------------------
# Modes and padding
# -------------------------
def pkcs5_pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len])*pad_len

def pkcs5_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len])*pad_len:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def des_encrypt_ecb(plaintext: bytes, key8: bytes) -> bytes:
    key_bits = bytes_to_bits(key8)
    subkeys = generate_subkeys(key_bits)
    pt_padded = pkcs5_pad(plaintext, 8)
    out = bytearray()
    for i in range(0, len(pt_padded), 8):
        block = pt_padded[i:i+8]
        bits = bytes_to_bits(block)
        enc_bits = des_block_encrypt(bits, subkeys)
        out.extend(bits_to_bytes(enc_bits))
    return bytes(out)

def des_decrypt_ecb(ciphertext: bytes, key8: bytes) -> bytes:
    key_bits = bytes_to_bits(key8)
    subkeys = generate_subkeys(key_bits)
    out = bytearray()
    if len(ciphertext) % 8 != 0:
        raise ValueError("Invalid ciphertext length")
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        bits = bytes_to_bits(block)
        dec_bits = des_block_decrypt(bits, subkeys)
        out.extend(bits_to_bytes(dec_bits))
    return pkcs5_unpad(bytes(out))

def des_encrypt_cbc(plaintext: bytes, key8: bytes, iv8: bytes) -> bytes:
    if len(iv8) != 8:
        raise ValueError("IV must be 8 bytes")
    key_bits = bytes_to_bits(key8)
    subkeys = generate_subkeys(key_bits)
    pt_padded = pkcs5_pad(plaintext, 8)
    out = bytearray()
    prev = iv8
    for i in range(0, len(pt_padded), 8):
        block = pt_padded[i:i+8]
        xored = bytes(a ^ b for a,b in zip(block, prev))
        bits = bytes_to_bits(xored)
        enc_bits = des_block_encrypt(bits, subkeys)
        enc_block = bits_to_bytes(enc_bits)
        out.extend(enc_block)
        prev = enc_block
    return bytes(out)

def des_decrypt_cbc(ciphertext: bytes, key8: bytes, iv8: bytes) -> bytes:
    if len(iv8) != 8:
        raise ValueError("IV must be 8 bytes")
    key_bits = bytes_to_bits(key8)
    subkeys = generate_subkeys(key_bits)
    out = bytearray()
    prev = iv8
    if len(ciphertext) % 8 != 0:
        raise ValueError("Invalid ciphertext length")
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        bits = bytes_to_bits(block)
        dec_bits = des_block_decrypt(bits, subkeys)
        dec_block = bits_to_bytes(dec_bits)
        xored = bytes(a ^ b for a,b in zip(dec_block, prev))
        out.extend(xored)
        prev = block
    return pkcs5_unpad(bytes(out))

# -------------------------
# Utilities for hex usage
# -------------------------
def hexstr_to_bytes(hexstr: str) -> bytes:
    hs = hexstr.strip()
    if hs.startswith("0x") or hs.startswith("0X"):
        hs = hs[2:]
    if len(hs) % 2 == 1:
        hs = "0" + hs
    return bytes.fromhex(hs)

def bytes_to_hexstr(b: bytes) -> str:
    return b.hex().upper()

# -------------------------
# Quick self-test with known vector
# -------------------------
def _self_test():
    # Known DES test vector:
    # Plaintext  0123456789ABCDEF
    # Key        133457799BBCDFF1
    # Ciphertext 85E813540F0AB405
    pt_hex = "0123456789ABCDEF"
    key_hex = "133457799BBCDFF1"
    expected_cipher_hex = "85E813540F0AB405"

    pt = hexstr_to_bytes(pt_hex)
    key = hexstr_to_bytes(key_hex)

    cipher = des_encrypt_ecb(pt, key)
    cipher_hex = bytes_to_hexstr(cipher)[:16]  # one block
    print("Plaintext:", pt_hex)
    print("Key:", key_hex)
    print("Expected Cipher:", expected_cipher_hex)
    print("Computed Cipher:", cipher_hex)

    if cipher_hex == expected_cipher_hex:
        print("Self-test PASSED")
    else:
        print("Self-test FAILED")

if __name__ == "__main__":
    _self_test()
