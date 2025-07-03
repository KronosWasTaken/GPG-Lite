import os
from aes.cbc_file import encrypt_cbc_file, decrypt_cbc_file
from kdf.argon2_kdf import generate_salt, derive_key
from rsa.rsa_core import rsa_encrypt_oaep, rsa_decrypt_oaep
import secrets

def hybrid_encrypt_file(infile, outfile, pubkey, password):
    salt = generate_salt()
    iv = secrets.token_bytes(16)
    aes_key = derive_key(password, salt, length=16)
    tmp_enc = outfile + ".aes.tmp"
    encrypt_cbc_file(infile, tmp_enc, aes_key, iv=iv)
    enc_key = rsa_encrypt_oaep(aes_key, pubkey)
    with open(outfile, 'wb') as out_f, open(tmp_enc, 'rb') as enc_f:
        out_f.write(salt)
        out_f.write(iv)
        out_f.write(len(enc_key).to_bytes(2, 'big'))
        out_f.write(enc_key)
        out_f.write(enc_f.read())
    os.remove(tmp_enc)

def hybrid_decrypt_file(infile, outfile, privkey, password):
    with open(infile, 'rb') as in_f:
        salt = in_f.read(16)
        iv = in_f.read(16)
        key_len = int.from_bytes(in_f.read(2), 'big')
        enc_key = in_f.read(key_len)
        ciphertext = in_f.read()
    aes_key = derive_key(password, salt, length=16)
    dec_aes_key = rsa_decrypt_oaep(enc_key, privkey)
    if aes_key != dec_aes_key:
        raise ValueError('Incorrect password or corrupted file (derived key does not match decrypted key)')
    tmp_enc = outfile + ".aes.tmp"
    with open(tmp_enc, 'wb') as tmp_f:
        tmp_f.write(ciphertext)
    decrypt_cbc_file(tmp_enc, outfile, aes_key, iv=iv)
    os.remove(tmp_enc) 