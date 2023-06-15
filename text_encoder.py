#!/usr/bin/env python3

import os
import string
import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encode_string_with_aes(input_string, secret_key, salt=None):
    # Convert the salt string to bytes if provided
    if salt is not None:
        salt = salt.encode('utf-8')

    # Generate a random salt if not provided
    if salt is None:
        salt = ''.join(random.choices(string.ascii_lowercase, k=16)).encode('utf-8')

    # Derive a key from the provided secret key and salt
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(secret_key.encode('utf-8'))

    # Generate a random IV
    iv = os.urandom(16)

    # Create a cipher object with AES-256 in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create an encryptor object
    encryptor = cipher.encryptor()

    # Pad the input string
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(input_string.encode('utf-8')) + padder.finalize()

    # Encrypt the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Concatenate the IV and the ciphertext
    encoded_string = iv + ciphertext

    return encoded_string, salt

def decode_string_with_aes(encoded_string, secret_key, salt):

    # Extract the IV from the encoded string
    iv = encoded_string[:16]

    # Extract the ciphertext from the encoded string
    ciphertext = encoded_string[16:]

    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(secret_key.encode('utf-8'))

    # Create a cipher object with AES-256 in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Create a decryptor object
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Create an unpadder object
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    # Unpad the decrypted data
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Decode the decrypted data back to a string
    decoded_string = unpadded_data.decode('utf-8')

    return decoded_string

def main():
    # Take input from the user
    choice = input("Enter 'e' to encode or 'd' to decode: ")

    secret_key = input("Enter the secret key: ")

    if choice == 'e':
        input_string = input("Enter a string to encode: ")
        use_custom_salt = input("Do you want to use a custom salt? (y/n): ")
        if use_custom_salt.lower() == 'y':
            custom_salt = input("Enter the custom salt: ")
            encoded_string, salt = encode_string_with_aes(input_string, secret_key, salt=custom_salt)
        else:
            encoded_string, salt = encode_string_with_aes(input_string, secret_key)
        print("Encoded string (with AES-256):", encoded_string.hex())  # Print the encoded string in hexadecimal format
        print("Salt (hexadecimal format):", salt.hex())  # Print the salt in hexadecimal format
    elif choice == 'd':
        encoded_string = bytes.fromhex(input("Enter the encoded string with AES-256(hexadecimal format): "))
        salt = bytes.fromhex(input("Enter the salt (hexadecimal format): "))
        decoded_string = decode_string_with_aes(encoded_string, secret_key, salt)
        print("Salt is: ", salt.decode('utf-8'))
        print("Decoded string:", decoded_string)
    else:
        print("Invalid choice. Please enter 'e' to encode or 'd' to decode.")

if __name__ == "__main__":
    main()
