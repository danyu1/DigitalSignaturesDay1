from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def verify_signature(public_key_file, message, signature):
    # Load the public key
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    try:
        # Verify the signature
        public_key.verify(
            bytes.fromhex(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

if __name__ == "__main__":
    public_key_file = 'public_key.pem'
    message = input("What is the message to decode.")
    signature = input("Enter the signature in hex format: ")
    verification_result = verify_signature(public_key_file, message, signature)
    if verification_result:
        print("Signature verified successfully.")
    else:
        print("Invalid signature.")

