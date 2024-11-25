from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa,ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from keypair.models import KeyPair
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
# DSA chuẩn rồi
def sign_dsa(keypair, hashed_message):
    # Load the private key from the PEM-encoded string
    private_key = serialization.load_pem_private_key(
        keypair.private_key.encode('utf-8'),
        password=None,
        backend=default_backend()
    )

    # DSA sử dụng phương thức sign để tạo chữ ký
    return private_key.sign(
        hashed_message,
        hashes.SHA256()  # DSA typically uses SHA256 for hashing
    )
def verify_dsa(keypair, hashed_message, signature):
    # Load the public key from the PEM-encoded string
    public_key = serialization.load_pem_public_key(
        keypair.public_key.encode('utf-8'),
        backend=default_backend()
    )
    
    try:
        # DSA uses the verify method to check the validity of the signature
        public_key.verify(
            signature,
            hashed_message,
            hashes.SHA256()  # DSA typically uses SHA256 for hashing
        )
        return True
    except:
        return False

# ECDSA chuẩn rồi
def sign_ecdsa(keypair, hashed_message):
    # Load the private key from the PEM-encoded string
    private_key = serialization.load_pem_private_key(
        keypair.private_key.encode('utf-8'),
        password=None,
        backend=default_backend()
    )

    # ECDSA ký với SHA256 hash
    return private_key.sign(
        hashed_message,
        ec.ECDSA(hashes.SHA256())  # Ký với thuật toán ECDSA và hash SHA256
    )
def verify_ecdsa(keypair, hashed_message, signature):
    # Load the public key from the PEM-encoded string
    public_key = serialization.load_pem_public_key(
        keypair.public_key.encode('utf-8'),
        backend=default_backend()
    )

    try:
        # Xác minh chữ ký ECDSA với SHA256 hash
        public_key.verify(
            signature,
            hashed_message,
            ec.ECDSA(hashes.SHA256())  # Xác minh chữ ký với thuật toán ECDSA và hash SHA256
        )
        return True  # Chữ ký hợp lệ
    except:
        return False  # Chữ ký không hợp lệ

# RSA chuẩn rồi 
def sign_rsa(keypair, hashed_message):
    private_key = serialization.load_pem_private_key(
        keypair.private_key.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    return private_key.sign(
        hashed_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_rsa(keypair, hashed_message, signature):
    public_key = serialization.load_pem_public_key(
        keypair.public_key.encode('utf-8'),
        backend=default_backend()
    )
    try:
        public_key.verify(
            signature,
            hashed_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# EdDSA đang lỗi phần tạo keypair
def sign_eddsa(keypair, message_hash):
    private_key = keypair.private_key
    signature = private_key.sign(message_hash)  # Sign the hash (bytes) directly
    # return base64.b64encode(signature).decode('utf-8')  # Return signature in Base64
    return signature

def verify_eddsa(keypair, hashed_message, signature):
    # Load the public key from the PEM-encoded string
    public_key = base64.b64decode(keypair.public_key)
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    signature = base64.b64decode(signature)

    return public_key.verify(signature, hashed_message)