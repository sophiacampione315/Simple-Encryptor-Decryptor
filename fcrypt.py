from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, utils, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys, argparse, os

def parse_args():
    parser = argparse.ArgumentParser(description='Encrypt/Decrypt')
    parser.add_argument('-e', '--encrypt', nargs=4)
    parser.add_argument('-d', '--decrypt', nargs=4)
    return parser.parse_args()

#Read public key for pem or der file
def read_public_key(key_path):
    with open(key_path, 'rb') as f:
        data = f.read()
        if data.startswith(b"-----BEGIN"):
            return serialization.load_pem_public_key(data)
        else:
            return serialization.load_der_public_key(data)

#Read private key for pem or der file
def read_private_key(key_path):
    with open(key_path, 'rb') as f:
        data = f.read()
        if data.startswith(b"-----BEGIN"):
            return serialization.load_pem_private_key(data, password=None)
        else:
            return serialization.load_der_private_key(data, password=None)

#Encrypt message with AES key
def encrypt_message_aes(message, key):
    nonce = os.urandom(12) 
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, message, None)
    return nonce + ciphertext

#Decrypt ciphertext
def decrypt_message_aes(encrypted_message, key):
    nonce = encrypted_message[:12]
    ciphertext = encrypted_message[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

#Encrypt AES key using RSA
def encrypt_aes_key_rsa(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

#Decrypt AES key
def decrypt_aes_key_rsa(encrypted_aes_key, private_key):
    return private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

#Sign message
def sign_message(message, private_key):  
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

#Verify message signature
def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def main():
    args = parse_args()

    #Encrypt
    if args.encrypt:
        pub_key_path = args.encrypt[0]
        priv_key_path = args.encrypt[1]
        input_plaintext_file = args.encrypt[2]
        ciphertext_file = args.encrypt[3]

        public_key = read_public_key(pub_key_path)     
        private_key = read_private_key(priv_key_path)  

        with open(input_plaintext_file, "rb") as f:
            message = f.read()

        aes_key = os.urandom(32)

        encrypted_message = encrypt_message_aes(message, aes_key)
        encrypted_aes_key = encrypt_aes_key_rsa(aes_key, public_key)
        signature = sign_message(encrypted_message, private_key)

        with open(ciphertext_file, "wb") as f:
            f.write(encrypted_message)

        with open("encrypted_aes_key_file", "wb") as f:
            f.write(encrypted_aes_key)

        with open("signature_file", "wb") as f:
            f.write(signature)

        print("Encryption and signing successful")

    #Decrypt
    if args.decrypt:
        priv_key_path = args.decrypt[0]
        pub_key_path = args.decrypt[1]
        ciphertext_file = args.decrypt[2]
        output_plaintext_file = args.decrypt[3]

        private_key = read_private_key(priv_key_path)  
        public_key = read_public_key(pub_key_path)     

        with open(ciphertext_file, "rb") as f:
            encrypted_message = f.read()

        with open("encrypted_aes_key_file", "rb") as f:
            encrypted_aes_key = f.read()

        with open("signature_file", "rb") as f:
            signature = f.read()

        if not verify_signature(encrypted_message, signature, public_key):
            print("Signature verification failed")
            return

        aes_key = decrypt_aes_key_rsa(encrypted_aes_key, private_key)
        decrypted_message = decrypt_message_aes(encrypted_message, aes_key)

        with open(output_plaintext_file, "wb") as f:
            f.write(decrypted_message) 

        print("Decryption and verification successful")

if __name__ == "__main__":
    main()

