from aes.cbc_file import encrypt_cbc_file, decrypt_cbc_file
from kdf.argon2_kdf import generate_salt, derive_key
from rsa.rsa_core import generate_rsa_keypair
from rsa.hybrid import hybrid_encrypt_file, hybrid_decrypt_file
from rsa.pem import save_private_pem, save_public_pem, load_private_pem, load_public_pem
import os
import pickle

def save_key(key, filename):
    with open(filename, 'wb') as f:
        pickle.dump(key, f)

def load_key(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)

def main():
    while True:
        print("Options:")
        print("1. AES password-based file encryption (CBC)")
        print("2. AES password-based file decryption (CBC)")
        print("3. Generate RSA keypair")
        print("4. Hybrid RSA+AES file encryption")
        print("5. Hybrid RSA+AES file decryption")
        print("6. Export RSA keys to PEM")
        print("7. Import RSA keys from PEM")
        print("q. Quit")
        choice = input("Select option: ").strip().lower()
        if choice == '1':
            password = input("Enter password: ")
            infile = input("Enter input file path: ").strip()
            outfile = input("Enter output file path: ").strip()
            salt = generate_salt()
            key = derive_key(password, salt)
            tmp_outfile = outfile + ".tmp"
            encrypt_cbc_file(infile, tmp_outfile, key)
            with open(outfile, 'wb') as out_f, open(tmp_outfile, 'rb') as tmp_f:
                out_f.write(salt)
                out_f.write(tmp_f.read())
            os.remove(tmp_outfile)
            print(f"File encrypted. Salt prepended to ciphertext in {outfile}.")
        elif choice == '2':
            password = input("Enter password: ")
            infile = input("Enter input file path: ").strip()
            outfile = input("Enter output file path: ").strip()
            with open(infile, 'rb') as f:
                salt = f.read(16)
                rest = f.read()
            key = derive_key(password, salt)
            tmp_infile = infile + ".tmp"
            with open(tmp_infile, 'wb') as tmp_f:
                tmp_f.write(rest)
            decrypt_cbc_file(tmp_infile, outfile, key)
            os.remove(tmp_infile)
        elif choice == '3':
            privfile = input("Enter private key output file: ").strip()
            pubfile = input("Enter public key output file: ").strip()
            pem = input("Save as PEM format? (y/n): ").strip().lower() == 'y'
            # Retry key generation until valid
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
            if pem:
                save_private_pem(priv, privfile)
                save_public_pem(pub, pubfile)
            else:
                save_key(priv, privfile)
                save_key(pub, pubfile)
            print(f"RSA keypair saved to {privfile} (private) and {pubfile} (public).")
        elif choice == '4':
            pubfile = input("Enter recipient public key file: ").strip()
            infile = input("Enter input file path: ").strip()
            outfile = input("Enter output file path: ").strip()
            password = input("Enter password for file encryption: ")
            pem = input("Is the public key in PEM format? (y/n): ").strip().lower() == 'y'
            if pem:
                pub = load_public_pem(pubfile)
            else:
                pub = load_key(pubfile)
            hybrid_encrypt_file(infile, outfile, pub, password)
        elif choice == '5':
            privfile = input("Enter your private key file: ").strip()
            infile = input("Enter input file path: ").strip()
            outfile = input("Enter output file path: ").strip()
            password = input("Enter password for file decryption: ")
            pem = input("Is the private key in PEM format? (y/n): ").strip().lower() == 'y'
            if pem:
                priv = load_private_pem(privfile)
            else:
                priv = load_key(privfile)
            hybrid_decrypt_file(infile, outfile, priv, password)
        elif choice == '6':
            privfile = input("Enter private key file to export: ").strip()
            pubfile = input("Enter public key file to export: ").strip()
            privpem = input("Enter PEM output file for private key: ").strip()
            pubpem = input("Enter PEM output file for public key: ").strip()
            priv = load_key(privfile)
            pub = load_key(pubfile)
            save_private_pem(priv, privpem)
            save_public_pem(pub, pubpem)
            print(f"Exported to {privpem} and {pubpem}.")
        elif choice == '7':
            privpem = input("Enter PEM private key file to import: ").strip()
            pubpem = input("Enter PEM public key file to import: ").strip()
            privfile = input("Enter output file for imported private key: ").strip()
            pubfile = input("Enter output file for imported public key: ").strip()
            priv = load_private_pem(privpem)
            pub = load_public_pem(pubpem)
            save_key(priv, privfile)
            save_key(pub, pubfile)
            print(f"Imported and saved as {privfile} and {pubfile}.")
        elif choice == 'q':
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main() 