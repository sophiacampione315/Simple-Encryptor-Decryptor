# Simple Encryptor/Decryptor Application
This is a simple Python application that can encrypt and sign a plaintext/ciphertext file, then decrypt and verify it. My design ensures confidentiality by using both asymmetric and symmetric encryption, and ensures authentication and integrity by signing and verifying.

Encryption: First, I used AES-GCM encryption to encrypt the plaintext. I chose this
primitive and mode as it can detect modifications to the ciphertext and is considered
secure. Then, I encrypted the AES key with RSA using OAEP padding. The reasoning
for this is that RSA is more secure, but it can only encrypt up to as large as the given
key size. Adding the signature to the message before encrypting adds more data, so
RSA would no longer be able to encrypt the plaintext. On the other hand, AES can
encrypt large files quickly, but sending an unencrypted AES key to its recipient is not
secure. Combining the two primitives allows for encryption that is both fast and secure.
This method is called key encapsulation. Using this method ensures that messages are
confidential and unmodified.

Signing: The ciphertext is signed with the sender’s RSA private key, which was
generated outside of the program. I used RSA for the signature as it is considered
secure and commonly used for signatures in real life. The program verifies the signature
before decrypting, ensuring that the message hasn’t been altered and was sent by the
correct party. This preserves the message’s integrity. Verifying the signature is valid also
verifies that the actual sender indeed sent the message, and not an attacker
pretending to be the sender.

Command for encryption and signing: python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file

Command for decryption and verifying: python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file
