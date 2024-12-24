from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.utils import timezone
from users.models import UserProfile
from cryptography.hazmat.primitives.asymmetric import dsa, ed25519, ec, rsa
from cryptography.hazmat.primitives import serialization
import base64
from django.http import HttpResponse
from io import BytesIO
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import KeyPair
from django.utils import timezone

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

# @login_required(login_url='users:login')
# @user_passes_test(lambda user: user.is_superuser)
# def generate_keypair(request):
#     if request.method == "POST":
#         verification_code = request.POST['verification_code']
#         user_profile = UserProfile.objects.filter(verification_code=verification_code).first()

#         # Check if user profile exists
#         if not user_profile:
#             messages.error(request, 'User with this verification code does not exist.')
#             return redirect('keypair:generate_keypair')

#         # Check if an active keypair already exists for this user
#         if KeyPair.objects.filter(user=user_profile.user, status='Active').exists():
#             messages.error(request, 'An active key pair already exists for this user.')
#             return redirect('keypair:generate_keypair')

#         # Get the selected algorithm and bit size
#         algorithm = request.POST['algorithm']
#         bit_size = int(request.POST['bit_size'])

#         # Generate the keypair based on the selected algorithm and bit size
#         if algorithm == 'RSA':
#             private_key, public_key = generate_rsa_keypair(bit_size)
#         elif algorithm == 'DSA':
#             private_key, public_key = generate_dsa_keypair(bit_size)
#         elif algorithm == 'ECDSA':
#             private_key, public_key = generate_ecdsa_keypair(bit_size)
#         else:
#             messages.error(request, 'Unsupported algorithm.')
#             return redirect('keypair:generate_keypair')

#             # Serialize keys to PEM format
#         private_key_pem = private_key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.TraditionalOpenSSL,
#             encryption_algorithm=serialization.NoEncryption()
#         )
#         public_key_pem = public_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ).decode('utf-8')

#         # Set created_at and expire fields
#         created_at = timezone.now()
#         expire = created_at + timezone.timedelta(days=365)  # 1 year expiration

#         # Save the keypair to the database
#         keypair = KeyPair.objects.create(
#             user=user_profile.user,
#             type=algorithm,
#             public_key=public_key_pem,
#             private_key=private_key_pem.decode('utf-8'),
#             created_at=created_at,
#             expire=expire,
#             status='Active'
#         )

#         # Create a response to send the private key as a download
#         response = HttpResponse(private_key_pem, content_type='application/pem')
#         response['Content-Disposition'] = f'attachment; filename="private_key_{keypair.type}.pem"'

#         # Add success message
#         messages.success(request, 'Key pair generated successfully!')

#         return response  # Return private key file as download

#     return render(request, 'keypair_form.html')

@api_view(['POST'])
def generate_keypair(request):
    """
    API để tạo keypair dựa trên verification_code, algorithm và bit_size.
    """
    verification_code = request.data.get('verification_code')
    algorithm = request.data.get('algorithm')
    bit_size = request.data.get('bit_size')

    # Kiểm tra input
    if not verification_code or not algorithm or not bit_size:
        return Response(
            {"error": "verification_code, algorithm, and bit_size are required."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Tìm UserProfile từ verification_code
    user_profile = UserProfile.objects.filter(verification_code=verification_code).first()
    if not user_profile:
        return Response(
            {"error": "User with this verification code does not exist."},
            status=status.HTTP_404_NOT_FOUND
        )

    # Kiểm tra xem đã có keypair active chưa
    if KeyPair.objects.filter(user=user_profile.user, status='Active').exists():
        return Response(
            {"error": "An active key pair already exists for this user."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Sinh keypair dựa trên thuật toán
    try:
        bit_size = int(bit_size)
        if algorithm == 'RSA':
            private_key, public_key = generate_rsa_keypair(bit_size)
        elif algorithm == 'DSA':
            private_key, public_key = generate_dsa_keypair(bit_size)
        elif algorithm == 'ECDSA':
            private_key, public_key = generate_ecdsa_keypair(bit_size)
        else:
            return Response(
                {"error": "Unsupported algorithm."},
                status=status.HTTP_400_BAD_REQUEST
            )
    except Exception as e:
        return Response(
            {"error": f"Failed to generate key pair: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

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

    # Lưu keypair vào database
    created_at = timezone.now()
    expire = created_at + timezone.timedelta(days=365)  # Expire sau 1 năm
    keypair = KeyPair.objects.create(
        user=user_profile.user,
        type=algorithm,
        public_key=public_key_pem,
        private_key=private_key_pem.decode('utf-8'),
        created_at=created_at,
        expire=expire,
        status='Active'
    )

    # Trả về phản hồi
    return Response(
        {
            "message": "Key pair generated successfully!",
            "public_key": public_key_pem,
            "private_key": private_key_pem.decode('utf-8'),
            "type": keypair.type,
            "created_at": created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "expire": expire.strftime('%Y-%m-%d %H:%M:%S'),
        },
        status=status.HTTP_201_CREATED
    )

@login_required(login_url='users:login')
@user_passes_test(lambda user: user.is_superuser)
def expire_keypair(request):
    if request.method == "POST":
        verification_code = request.POST['verification_code_expire']
        user_profile = UserProfile.objects.filter(verification_code=verification_code).first()

        # Check if user profile exists
        if not user_profile:
            messages.error(request, 'Mã xác thực không tồn tại.')
            return redirect('keypair:expire_keypair')

        # Find the active keypair associated with this user
        keypair = KeyPair.objects.filter(user=user_profile.user, status='Active').first()
        if keypair:
            keypair.status = 'Expired'
            keypair.save()
            messages.success(request, 'Thu Hồi Khóa Thành Công!')
        else:
            messages.error(request, 'Người dùng không có khóa nào cần thu hồi.')

        return redirect('keypair:expire_keypair')

    return render(request, 'keypair_expire_form.html')




# @api_view(['POST'])
# def expire_keypair(request):
#     """
#     API để vô hiệu hóa keypair dựa trên verification_code
#     """
#     verification_code = request.data.get('verification_code_expire')

#     # Kiểm tra verification_code có được gửi không
#     if not verification_code:
#         return Response(
#             {"error": "Verification code is required."},
#             status=status.HTTP_400_BAD_REQUEST
#         )

#     # Lấy user_profile từ verification_code
#     user_profile = UserProfile.objects.filter(verification_code=verification_code).first()

#     if not user_profile:
#         return Response(
#             {"error": "User with this verification code does not exist."},
#             status=status.HTTP_404_NOT_FOUND
#         )

#     # Tìm keypair active liên kết với user
#     keypair = KeyPair.objects.filter(user=user_profile.user, status='Active').first()
#     if keypair:
#         keypair.status = 'Expired'
#         keypair.save()
#         return Response(
#             {"message": "Key pair expired successfully!"},
#             status=status.HTTP_200_OK
#         )
#     else:
#         return Response(
#             {"error": "No active key pair found for this user."},
#             status=status.HTTP_404_NOT_FOUND
#         )
