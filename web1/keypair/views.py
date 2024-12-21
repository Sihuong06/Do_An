from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils import timezone
from .models import KeyPair
from users.models import UserProfile
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, ec, rsa
from cryptography.hazmat.primitives import serialization
import base64
from django.http import HttpResponse
from io import BytesIO
from django.views.decorators.csrf import csrf_exempt

# DSA keypair generation
def generate_dsa_keypair(bit_size):
    private_key = dsa.generate_private_key(key_size=bit_size)
    public_key = private_key.public_key()
    return private_key, public_key

# ECDSA keypair generation (using SECP256R1, SECP384R1, SECP521R1)
def generate_ecdsa_keypair(bit_size):
    if bit_size == 256:
        curve = ec.SECP256R1()
    elif bit_size == 384:
        curve = ec.SECP384R1()
    elif bit_size == 521:
        curve = ec.SECP521R1()
    else:
        raise ValueError("Unsupported ECDSA bit size")

    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key


def generate_rsa_keypair(bit_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bit_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key

@csrf_exempt
@login_required(login_url='users:login')
@user_passes_test(lambda user: user.is_superuser)
def generate_keypair(request):
    if request.method == "POST":
        verification_code = request.POST['verification_code']
        user_profile = UserProfile.objects.filter(verification_code=verification_code).first()

        # Check if user profile exists
        if not user_profile:
            messages.error(request, 'User with this verification code does not exist.')
            return redirect('keypair:generate_keypair')

        # Check if an active keypair already exists for this user
        if KeyPair.objects.filter(user=user_profile.user, status='Active').exists():
            messages.error(request, 'An active key pair already exists for this user.')
            return redirect('keypair:generate_keypair')

        # Get the selected algorithm and bit size
        algorithm = request.POST['algorithm']
        bit_size = int(request.POST['bit_size'])

        # Generate the keypair based on the selected algorithm and bit size
        if algorithm == 'RSA':
            private_key, public_key = generate_rsa_keypair(bit_size)
        elif algorithm == 'DSA':
            private_key, public_key = generate_dsa_keypair(bit_size)
        elif algorithm == 'ECDSA':
            private_key, public_key = generate_ecdsa_keypair(bit_size)
        else:
            messages.error(request, 'Unsupported algorithm.')
            return redirect('keypair:generate_keypair')

            # Serialize keys to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Set created_at and expire fields
        created_at = timezone.now()
        expire = created_at + timezone.timedelta(days=365)  # 1 year expiration

        # Save the keypair to the database
        keypair = KeyPair.objects.create(
            user=user_profile.user,
            type=algorithm,
            public_key=public_key_pem,
            private_key=private_key_pem.decode('utf-8'),
            created_at=created_at,
            expire=expire,
            status='Active'
        )

        # Create a response to send the private key as a download
        response = HttpResponse(private_key_pem, content_type='application/pem')
        response['Content-Disposition'] = f'attachment; filename="private_key_{keypair.type}.pem"'

        # Add success message
        messages.success(request, 'Key pair generated successfully!')

        return response  # Return private key file as download

    return render(request, 'keypair_form.html')

@csrf_exempt
@login_required(login_url='users:login')
@user_passes_test(lambda user: user.is_superuser)
def expire_keypair(request):
    if request.method == "POST":
        verification_code = request.POST['verification_code_expire']
        user_profile = UserProfile.objects.filter(verification_code=verification_code).first()

        # Check if user profile exists
        if not user_profile:
            messages.error(request, 'User with this verification code does not exist.')
            return redirect('keypair:expire_keypair')

        # Find the active keypair associated with this user
        keypair = KeyPair.objects.filter(user=user_profile.user, status='Active').first()
        if keypair:
            keypair.status = 'Expired'
            keypair.save()
            messages.success(request, 'Key pair expired successfully!')
        else:
            messages.error(request, 'No active key pair found for this user.')

        return redirect('keypair:expire_keypair')

    return render(request, 'keypair_expire_form.html')
