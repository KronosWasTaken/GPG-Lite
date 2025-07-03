import random
import secrets
from math import gcd
import hashlib

def is_prime(n, k=64):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        p = secrets.randbits(bits)
        p |= (1 << bits - 1) | 1
        if is_prime(p, k=64):
            return p

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def validate_rsa_key(p, q, e, nbits):
    if p == q:
        raise ValueError('p and q must be different primes')
    n = p * q
    if n.bit_length() != nbits:
        raise ValueError('Modulus does not have the required bit length')
    if gcd(e, p - 1) != 1 or gcd(e, q - 1) != 1:
        raise ValueError('e must be coprime to p-1 and q-1')
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError('e must be coprime to phi(n)')

def generate_rsa_keypair(bits=2048, e=65537):
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1 and gcd(e, p - 1) == 1 and gcd(e, q - 1) == 1:
            d = modinv(e, phi)
            validate_rsa_key(p, q, e, bits)
            return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}

def mgf1(seed: bytes, length: int, hash_func=hashlib.sha256) -> bytes:
    counter = 0
    output = b''
    while len(output) < length:
        C = counter.to_bytes(4, 'big')
        output += hash_func(seed + C).digest()
        counter += 1
    return output[:length]

def oaep_encode(message: bytes, k: int, label: bytes = b'', hash_func=hashlib.sha256) -> bytes:
    hLen = hash_func().digest_size
    mLen = len(message)
    if mLen > k - 2 * hLen - 2:
        raise ValueError('Message too long for OAEP')
    lHash = hash_func(label).digest()
    ps = b'\x00' * (k - mLen - 2 * hLen - 2)
    db = lHash + ps + b'\x01' + message
    seed = secrets.token_bytes(hLen)
    dbMask = mgf1(seed, k - hLen - 1, hash_func)
    maskedDB = bytes(x ^ y for x, y in zip(db, dbMask))
    seedMask = mgf1(maskedDB, hLen, hash_func)
    maskedSeed = bytes(x ^ y for x, y in zip(seed, seedMask))
    return b'\x00' + maskedSeed + maskedDB

def oaep_decode(em: bytes, k: int, label: bytes = b'', hash_func=hashlib.sha256) -> bytes:
    hLen = hash_func().digest_size
    if len(em) != k or em[0] != 0:
        raise ValueError('Decryption error (OAEP)')
    maskedSeed = em[1:1 + hLen]
    maskedDB = em[1 + hLen:]
    seedMask = mgf1(maskedDB, hLen, hash_func)
    seed = bytes(x ^ y for x, y in zip(maskedSeed, seedMask))
    dbMask = mgf1(seed, k - hLen - 1, hash_func)
    db = bytes(x ^ y for x, y in zip(maskedDB, dbMask))
    lHash = hash_func(label).digest()
    if db[:hLen] != lHash:
        raise ValueError('Decryption error (OAEP lHash)')
    # Find the 0x01 separator
    idx = db.find(b'\x01', hLen)
    if idx == -1:
        raise ValueError('Decryption error (OAEP no 0x01)')
    return db[idx + 1:]

def rsa_encrypt_oaep(message: bytes, pubkey, label: bytes = b'') -> bytes:
    n, e = pubkey['n'], pubkey['e']
    k = (n.bit_length() + 7) // 8
    em = oaep_encode(message, k, label)
    m = bytes_to_int(em)
    if m >= n:
        raise ValueError('Message too large for the key size')
    c = pow(m, e, n)
    return int_to_bytes(c, k)

def rsa_decrypt_oaep(ciphertext: bytes, privkey, label: bytes = b'') -> bytes:
    n, d = privkey['n'], privkey['d']
    k = (n.bit_length() + 7) // 8
    c = bytes_to_int(ciphertext)
    if c >= n:
        raise ValueError('Ciphertext too large for the key size')
    m = pow(c, d, n)
    em = int_to_bytes(m, k)
    return oaep_decode(em, k, label)

def int_to_bytes(i, length=None):
    b = i.to_bytes((i.bit_length() + 7) // 8, 'big')
    if length:
        b = b.rjust(length, b'\x00')
    return b

def bytes_to_int(b):
    return int.from_bytes(b, 'big') 