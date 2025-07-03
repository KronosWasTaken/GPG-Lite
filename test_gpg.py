import os
import pickle
import random
import string
from rsa.rsa_core import generate_rsa_keypair
from rsa.hybrid import hybrid_encrypt_file, hybrid_decrypt_file

# Key save/load (matches main.py)
def save_key(key, filename):
    with open(filename, 'wb') as f:
        pickle.dump(key, f)

def load_key(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)

def random_text(length=64):
    return ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=length))

def random_password(length=12):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Test files
PLAINTEXT = 'test.txt'
ENCRYPTED = 'test.enc'
DECRYPTED = 'test.dec.txt'
PRIVKEY = 'priv.key'
PUBKEY = 'pub.key'

N_RUNS = 3  # Number of test runs
all_passed = True

for run in range(1, N_RUNS + 1):
    print(f"\n=== Test Run {run} ===")
    try:
        # 1. Generate random test file (write as UTF-8 bytes)
        test_message = random_text(64)
        with open(PLAINTEXT, 'wb') as f:
            f.write(test_message.encode('utf-8'))
        print(f"[+] Test file '{PLAINTEXT}' created.")

        # 2. Generate RSA keypair (retry until valid)
        print("[+] Generating RSA keypair...")
        while True:
            try:
                priv = generate_rsa_keypair()
                break
            except ValueError as e:
                if "Modulus does not have the required bit length" in str(e):
                    continue
                else:
                    raise
        pub = {'n': priv['n'], 'e': priv['e']}
        save_key(priv, PRIVKEY)
        save_key(pub, PUBKEY)
        print(f"[+] Keys saved as '{PRIVKEY}' and '{PUBKEY}'.")

        # 3. Generate random password
        password = random_password()
        print(f"[+] Using password: {password}")

        # 4. Encrypt file
        print("[+] Encrypting file...")
        hybrid_encrypt_file(PLAINTEXT, ENCRYPTED, pub, password)
        print(f"[+] Encrypted file saved as '{ENCRYPTED}'.")

        # 5. Decrypt file
        print("[+] Decrypting file...")
        priv_loaded = load_key(PRIVKEY)
        hybrid_decrypt_file(ENCRYPTED, DECRYPTED, priv_loaded, password)
        print(f"[+] Decrypted file saved as '{DECRYPTED}'.")

        # 6. Check if decrypted matches original (compare as bytes)
        with open(PLAINTEXT, 'rb') as f1, open(DECRYPTED, 'rb') as f2:
            orig = f1.read()
            dec = f2.read()
            if orig == dec:
                print("[PASS] Decrypted file matches original!")
            else:
                print("[FAIL] Decrypted file does NOT match original.")
                print(f"[DEBUG] Original length: {len(orig)}, Decrypted length: {len(dec)}")
                # Print hex diff (first 64 bytes)
                print(f"[DEBUG] Original (hex): {orig[:64].hex()}")
                print(f"[DEBUG] Decrypted(hex): {dec[:64].hex()}")
                all_passed = False
    except Exception as e:
        print(f"[ERROR] Exception during test run {run}: {e}")
        all_passed = False
    finally:
        # Cleanup
        for fname in [PLAINTEXT, ENCRYPTED, DECRYPTED, PRIVKEY, PUBKEY]:
            try:
                os.remove(fname)
            except Exception:
                pass

if all_passed:
    print(f"\n=== ALL {N_RUNS} TESTS PASSED ===")
else:
    print(f"\n=== SOME TESTS FAILED ===") 