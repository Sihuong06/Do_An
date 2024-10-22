from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import user_passes_test, login_required
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from django.utils import timezone
from users.models import UserProfile
from .models import KeyPair

@login_required(login_url='users:login')
@user_passes_test(lambda user: user.is_superuser)
def generate_keypair(request, verification_code):
    # Find the user by verification_code
    user_profile = get_object_or_404(UserProfile, verification_code=verification_code)

    # Check for existing active key pairs
    if KeyPair.objects.filter(user=user_profile.user, status='Active').exists():
        return JsonResponse({'error': 'An active key pair already exists for this user.'}, status=400)

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')  # Convert bytes to string for storage
    
    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')  # Convert bytes to string for storage

    # Set created_at to the current time and expire to one year later
    created_at = timezone.now()
    expire = created_at + timezone.timedelta(days=365)  # Set expire to one year from now

    # Save the key pair to the database
    keypair = KeyPair.objects.create(
        user=user_profile.user,  # user is a User instance
        public_key=public_key_pem,  # Store public key as PEM
        private_key=private_key_pem,  # Store private key as PEM
        status='Active',  # Set initial status
        created_at=created_at,
        expire=expire,
    )

    return JsonResponse({'message': 'Key pair generated successfully!', 'keypair_id': keypair.id})
@login_required(login_url='users:login')
@user_passes_test(lambda user: user.is_superuser)  # Ensure only superusers can access this view
def expire_keypair(request, verification_code):
    # Find the user by verification_code
    user_profile = get_object_or_404(UserProfile, verification_code=verification_code)

    # Retrieve the active key pair for the user
    keypair = get_object_or_404(KeyPair, user=user_profile.user, status='Active')  # Ensure user is User instance

    # Update the key pair status to 'Expired'
    keypair.status = 'Expired'
    keypair.save()

    return JsonResponse({'message': 'Key pair status updated to Expired successfully!'})
