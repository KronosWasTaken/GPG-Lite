import base64
from typing import Dict

# DER length encoding helper

def der_len(n):
    if n < 128:
        return bytes([n])
    else:
        s = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(s)]) + s

# DER length parsing helper
def der_parse_len(data: bytes, idx: int):
    first = data[idx]
    if first < 128:
        return first, idx + 1
    else:
        nbytes = first & 0x7F
        val = int.from_bytes(data[idx+1:idx+1+nbytes], 'big')
        return val, idx + 1 + nbytes

# Minimal ASN.1 DER encoding helpers for integers and sequences

def der_encode_integer(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, 'big')
    if b[0] & 0x80:
        b = b'\x00' + b
    return b'\x02' + der_len(len(b)) + b

def der_encode_sequence(*args: bytes) -> bytes:
    content = b''.join(args)
    return b'\x30' + der_len(len(content)) + content

# PKCS#1 RSAPrivateKey (n, e, d, p, q)
def encode_rsa_private_key(priv: Dict) -> bytes:
    # version=0, n, e, d, p, q, exp1, exp2, coeff
    n, e, d, p, q = priv['n'], priv['e'], priv['d'], priv['p'], priv['q']
    exp1 = d % (p - 1)
    exp2 = d % (q - 1)
    coeff = pow(q, -1, p)
    seq = der_encode_sequence(
        der_encode_integer(0),
        der_encode_integer(n),
        der_encode_integer(e),
        der_encode_integer(d),
        der_encode_integer(p),
        der_encode_integer(q),
        der_encode_integer(exp1),
        der_encode_integer(exp2),
        der_encode_integer(coeff),
    )
    return seq

# PKCS#1 RSAPublicKey (n, e)
def encode_rsa_public_key(pub: Dict) -> bytes:
    n, e = pub['n'], pub['e']
    seq = der_encode_sequence(
        der_encode_integer(n),
        der_encode_integer(e),
    )
    return seq

def pem_wrap(der: bytes, label: str) -> str:
    b64 = base64.encodebytes(der).replace(b'\n', b'')
    lines = [f"-----BEGIN {label}-----"]
    for i in range(0, len(b64), 64):
        lines.append(b64[i:i+64].decode())
    lines.append(f"-----END {label}-----")
    return '\n'.join(lines)

def save_private_pem(priv: Dict, filename: str):
    der = encode_rsa_private_key(priv)
    pem = pem_wrap(der, "RSA PRIVATE KEY")
    with open(filename, 'w') as f:
        f.write(pem)

def save_public_pem(pub: Dict, filename: str):
    der = encode_rsa_public_key(pub)
    pem = pem_wrap(der, "RSA PUBLIC KEY")
    with open(filename, 'w') as f:
        f.write(pem)

# Minimal DER/PEM parsing for public/private keys
def der_parse_integer(data: bytes, idx: int):
    assert data[idx] == 0x02
    length, idx = der_parse_len(data, idx+1)
    val = int.from_bytes(data[idx:idx+length], 'big')
    return val, idx+length

def der_parse_sequence(data: bytes, idx: int):
    assert data[idx] == 0x30
    length, idx = der_parse_len(data, idx+1)
    return idx, idx+length

def load_private_pem(filename: str) -> Dict:
    with open(filename, 'r') as f:
        lines = [line.strip() for line in f if not line.startswith('-----')]
    der = base64.b64decode(''.join(lines))
    idx, end = der_parse_sequence(der, 0)
    version, idx = der_parse_integer(der, idx)
    n, idx = der_parse_integer(der, idx)
    e, idx = der_parse_integer(der, idx)
    d, idx = der_parse_integer(der, idx)
    p, idx = der_parse_integer(der, idx)
    q, idx = der_parse_integer(der, idx)
    # skip exp1, exp2, coeff
    for _ in range(3):
        _, idx = der_parse_integer(der, idx)
    return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}

def load_public_pem(filename: str) -> Dict:
    with open(filename, 'r') as f:
        lines = [line.strip() for line in f if not line.startswith('-----')]
    der = base64.b64decode(''.join(lines))
    idx, end = der_parse_sequence(der, 0)
    n, idx = der_parse_integer(der, idx)
    e, idx = der_parse_integer(der, idx)
    return {'n': n, 'e': e} 