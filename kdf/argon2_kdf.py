import os
from argon2.low_level import hash_secret_raw, Type

def generate_salt(length=16):
    return os.urandom(length)

def derive_key(password, salt, length=16):
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        hash_len=length,
        type=Type.I
    ) 