from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

def generate_keys():
    # Check if the keys already exist
    if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
        # Generate the private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Serialize and save the private key
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open('private_key.pem', 'wb') as f:
            f.write(pem)

        # Serialize and save the public key
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open('public_key.pem', 'wb') as f:
            f.write(pem)
        print("Keys generated and saved.")
    else:
        print("Keys already exist.")

def sign_message(message):
    # Load the private key
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # Sign the message
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Output the signature
    return signature

if __name__ == "__main__":
    generate_keys()
    message = input("Enter a message to sign:  ")
    signature = sign_message(message)
    print(f"Message: {message}")
    print(f"Signature: {signature.hex()}")
    print(f"A public key is in this folder as public_key.pem.  Please copy and submit that with your homework")

