import os
from .state import State
from .key_expansion import key_expansion
from .utils import pad, unpad

def encrypt_block(plaintext, key):
    round_keys = key_expansion(key)
    state = State(plaintext)
    state.add_round_key(round_keys[0])
    for r in range(1, 10):
        state.sub_bytes()
        state.shift_rows()
        state.mix_columns()
        state.add_round_key(round_keys[r])
    state.sub_bytes()
    state.shift_rows()
    state.add_round_key(round_keys[10])
    out = bytearray(16)
    for row in range(4):
        for col in range(4):
            out[col * 4 + row] = state.matrix[row][col]
    return bytes(out)

def decrypt_block(ciphertext, key):
    round_keys = key_expansion(key)
    state = State(ciphertext)
    state.add_round_key(round_keys[10])
    for r in range(9, 0, -1):
        state.inv_shift_rows()
        state.inv_sub_bytes()
        state.add_round_key(round_keys[r])
        state.inv_mix_columns()
    state.inv_shift_rows()
    state.inv_sub_bytes()
    state.add_round_key(round_keys[0])
    out = bytearray(16)
    for row in range(4):
        for col in range(4):
            out[col * 4 + row] = state.matrix[row][col]
    return bytes(out)

def encrypt_cbc_file(infile, outfile, key, iv=None):
    generated_iv = False
    if iv is None:
        iv = os.urandom(16)
        generated_iv = True
    with open(infile, 'rb') as f:
        plaintext = f.read()
    padded = pad(plaintext)
    ciphertext = b''
    prev = iv
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = encrypt_block(xored, key)
        ciphertext += enc
        prev = enc
    with open(outfile, 'wb') as f:
        if generated_iv:
            f.write(iv)
        f.write(ciphertext)

def decrypt_cbc_file(infile, outfile, key, iv=None):
    with open(infile, 'rb') as f:
        data = f.read()
    if iv is None:
        iv = data[:16]
        ciphertext = data[16:]
    else:
        ciphertext = data
    prev = iv
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = decrypt_block(block, key)
        xored = bytes(a ^ b for a, b in zip(dec, prev))
        plaintext += xored
        prev = block
    try:
        unpadded = unpad(plaintext)
    except Exception as e:
        print("Decryption failed:", e)
        return
    with open(outfile, 'wb') as f:
        f.write(unpadded) 