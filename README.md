# GPG-Lite Python Encryption Tool

A simple, modular, and educational GPG encryption tool in Python. Supports AES (CBC mode), Argon2 password-based key derivation, FIPS-style RSA with OAEP, PKCS#1 PEM/DER key export/import, and hybrid encryption. Designed for CLI use, with a focus on security, clarity, and best practices.

---

## Features
- **AES-128 CBC** file encryption/decryption with PKCS#7 padding
- **Password-based key derivation** using Argon2
- **RSA key generation** (FIPS-style, 2048 bits by default)
- **Hybrid encryption**: RSA-OAEP for AES key, AES for file data
- **PEM/DER export/import** for RSA keys (PKCS#1)
- **Menu-driven CLI** (no GUI)
- **Test script** for end-to-end validation

---

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/KronosWasTaken/GPG-Lite.git
   cd GPG
   ```
2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

---

## Usage

Run the main program:
```sh
python main.py
```
You will see a menu with options:

```
Options:
1. AES password-based file encryption (CBC)
2. AES password-based file decryption (CBC)
3. Generate RSA keypair
4. Hybrid RSA+AES file encryption
5. Hybrid RSA+AES file decryption
6. Export RSA keys to PEM
7. Import RSA keys from PEM
q. Quit
```

---

### **Step-by-Step: Secure File Exchange**

#### **A. Your Friend Generates Their RSA Key Pair**
1. Run `python main.py` and select option `3` (Generate RSA keypair).
2. Enter file names for private and public keys (e.g., `friend_private.pem`, `friend_public.pem`).
3. Choose PEM format (`y`).
4. Your friend sends you their public key file (`friend_public.pem`).

#### **B. You Encrypt a File for Your Friend**
1. Run `python main.py` and select option `4` (Hybrid RSA+AES file encryption).
2. Enter the path to your friend's public key file (`friend_public.pem`).
3. Enter the file you want to encrypt (e.g., `secret.txt`).
4. Enter the output file name (e.g., `encrypted.txt`).
5. Enter a password for file encryption (this protects the AES key).
6. Indicate the public key is in PEM format (`y`).
7. Send the resulting `encrypted.txt` to your friend.

#### **C. Your Friend Decrypts the File**
1. Run `python main.py` and select option `5` (Hybrid RSA+AES file decryption).
2. Enter the path to their private key file (`friend_private.pem`).
3. Enter the path to the encrypted file (`encrypted.txt`).
4. Enter the output file name for the decrypted file (e.g., `decrypted.txt`).
5. Enter the password you used for file encryption.
6. Indicate the private key is in PEM format (`y`).
7. The decrypted file will be saved as `decrypted.txt`.

---

### **Other Features**
- **AES-only encryption/decryption:** Use options 1 and 2 for password-based file encryption without RSA.
- **Export/Import RSA keys to/from PEM:** Use options 6 and 7 to convert between pickle and PEM formats.

---

## Testing
Run the test script to verify everything works:
```sh
python test_gpg.py
```

---

## Security Notes
- **Never share your private key.** Only share your public key.
- **Always use your friend's public key to encrypt files for them.**
- **Your friend must use their private key to decrypt.**
- **Passwords** are used to protect the AES key in hybrid mode.

---