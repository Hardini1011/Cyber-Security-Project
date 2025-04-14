import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import getpass
import os
import re

# AES Encryption-Decryption Constants
BLOCK_SIZE = 16


def sha256(key):
    """Hash the key using SHA-256."""
    sha = hashlib.sha256()
    sha.update(key.encode("utf-8"))
    return sha.digest()


def pad(plain_text, block):
    """Pad the plaintext to make it a multiple of the block size."""
    pad_len = block - (len(plain_text) % block)
    return plain_text + (chr(pad_len) * pad_len).encode("utf-8")


def unpad(plain_text):
    """Remove padding from the decrypted text."""
    return plain_text[:-ord(plain_text[-1:])]


def encrypt_image(file_path, key):
    """Encrypt an image file using AES."""
    with open(file_path, "rb") as f:
        image_data = f.read()

    key = sha256(key)
    iv = Random.new().read(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(image_data, BLOCK_SIZE))

    enc_file_path = "encrypted_image.aes"
    with open(enc_file_path, "wb") as f:
        f.write(base64.b64encode(iv + encrypted_data))

    print(f"🔒 Image encrypted successfully! Saved as {enc_file_path}")


def decrypt_image(encrypted_file_path, key):
    """Decrypt an AES encrypted image."""
    with open(encrypted_file_path, "rb") as f:
        encrypted_data = base64.b64decode(f.read())

    key = sha256(key)
    iv = encrypted_data[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[BLOCK_SIZE:]))

    dec_file_path = "decrypted_image.png"
    with open(dec_file_path, "wb") as f:
        f.write(decrypted_data)

    print(f"🔓 Image decrypted successfully! Saved as {dec_file_path}")


def check_password_strength(password):
    """Check password strength and return level."""
    errors = []

    if len(password) < 8:
        errors.append("❌ Password must be at least 8 characters long.")
    if len(password) > 16:
        errors.append("❌ Password must not exceed 16 characters.")
    if not re.search(r"[A-Z]", password):
        errors.append("❌ Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("❌ Password must contain at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        errors.append("❌ Password must contain at least one number.")
    if not re.search(r"[!@#$%^&*()-_=+]", password):
        errors.append("❌ Password must contain at least one special character (!@#$%^&*()-_=+).")

    if errors:
        print("\n⚠️ Your password does not meet the following requirements:")
        for err in errors:
            print(err)
        return False

    print("✅ Strong password! Login successful.")
    return True


def login():
    """Force user to enter a username and a strong password before proceeding."""
    username = input("Enter your username: ").strip()
    if not username:
        print("❌ Username cannot be empty!")
        return False
    
    while True:
        password = getpass.getpass("Enter your password: ")
        if check_password_strength(password):
            print(f"\n✅ Welcome, {username}! You are now logged in.")
            return True

def main():
    print("🔐 Secure Login System")

    # Enforce strong password for login
    if not login():
        return

    while True:
        print("\n📌 Choose an option:")
        print("1️⃣ Encrypt an Image")
        print("2️⃣ Decrypt an Image")
        print("3️⃣ Exit")

        choice = input("Enter your choice (1-3): ").strip()

        if choice == "1":
            file_path = input("Enter the image file path: ").strip()
            if not os.path.exists(file_path):
                print("❌ File not found!")
                continue
            key = getpass.getpass("Enter encryption key: ")
            encrypt_image(file_path, key)

        elif choice == "2":
            encrypted_file_path = input("Enter the encrypted file path: ").strip()
            if not os.path.exists(encrypted_file_path):
                print("❌ File not found!")
                continue
            key = getpass.getpass("Enter decryption key: ")
            decrypt_image(encrypted_file_path, key)

        elif choice == "3":
            print("🔚 Exiting... Have a great day!")
            break

        else:
            print("❌ Invalid choice. Please enter a number between 1-3.")


if __name__ == "__main__":
    main()
