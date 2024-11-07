from django.shortcuts import render, redirect, get_object_or_404
from django.core.files.storage import FileSystemStorage
from .models import File
from reportlab.lib.pagesizes import letter
from keypair.models import KeyPair
from users.models import UserProfile
from picture.models import Picture
from .forms import FileUploadForm  # Tạo form upload file
from django.contrib.auth import authenticate, login,logout
from django.contrib.auth.decorators import login_required, user_passes_test
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from PyPDF2 import PdfReader, PdfWriter
import logging
import logging.config
from django.http import HttpResponse
import os
from django.http import FileResponse
from reportlab.pdfgen import canvas
import io
import uuid
from django.core.files.storage import FileSystemStorage
from django.conf import settings
from PIL import Image, ImageDraw, ImageFont
import fitz

logging.basicConfig(
    level=logging.DEBUG,  # Adjust the level to DEBUG, INFO, WARNING, etc.
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.StreamHandler(),  # Logs to the console
        logging.FileHandler('debug.log'),  # Logs to a file
    ]
)


@login_required(login_url='users:login')
# Upload file và hiển thị nội dung
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.save(commit=False)
            uploaded_file.user = request.user
            uploaded_file.status = 'Unsigned' 
            uploaded_file.save()
            picture = Picture.objects.all()
            file_obj = get_object_or_404(File, id=uploaded_file.id)
            file_url = file_obj.file_path.url
            return render(request, 'files/file_detail.html', {'file_url': file_url, 'file_obj': file_obj,'picture':picture})
    else:
        form = FileUploadForm()
    return render(request, 'files/upload_file.html', {'form': form})


@login_required(login_url='users:login')
def view_file(request, file_id):
    file_obj = get_object_or_404(File, id=file_id)
    file_url = file_obj.file_path.url  # URL của file PDF được upload
    key_pair = KeyPair.objects.filter(user=request.user, status='Active').first()
    picture = Picture.objects.all()
    logger = logging.getLogger('applog')
    if key_pair:
        logger.info('Key pair found')
    else:
        logger.error('No active key pair found')
    # Render trang HTML tùy chỉnh và truyền file URL vào template
    return render(request, 'files/file_detail.html', {'file_url': file_url, 'file_obj': file_obj,'picture':picture})
    
@login_required(login_url='users:login')
def list_files(request):
    status = request.GET.get('status', 'all')
    order_by = request.GET.get('order_by', 'date_signed')
    order = request.GET.get('order', 'asc')

    # Filtering logic with user filtering
    if status != 'all':
        files = File.objects.filter(user=request.user, status=status)
    else:
        files = File.objects.filter(user=request.user)

    # Sorting logic
    if order == 'desc':
        files = files.order_by(f'-{order_by}')
    else:
        files = files.order_by(order_by)

    return render(request, 'files/file_list.html', {'files': files, 'status': status})



def gen_sig(keypair,file):
    # Load the private key from the PEM-encoded string
    private_key = serialization.load_pem_private_key(
        keypair.private_key.encode('utf-8'),
        password=None,
        backend=default_backend()
    )

    # Read the PDF file
    reader = PdfReader(file.file_path)
    content = ''
    for page_num in range(len(reader.pages)-1):
        page = reader.pages[page_num]
        content += page.extract_text() if page.extract_text() else ''
    
    # Create a hash of the PDF content
    content_bytes = content.encode('utf-8')
    hash_value = hashlib.sha256(content_bytes).digest()
    logger = logging.getLogger('applog')

    logger.info(f'Hash value: {hash_value.hex()}')
    # Generate the signature
    signature = private_key.sign(
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

def get_image_size(image_path):
    # Open the image file
    with Image.open(image_path) as img:
        width, height = img.size  # Get width and height of the image
    return width, height

def insert_image_in_pdf(original_pdf_path, image_path, page_number):
    img_width, img_height = get_image_size(image_path)
    pdf_document = fitz.open(original_pdf_path)
    page = pdf_document[page_number]
    
    page_width = page.rect.width
    page_height = page.rect.height
    
    x = page_width - img_width - 60
    y = page_height - img_height - 600
    rect = fitz.Rect(x, y, x + img_width, y + img_height)
    
    page.insert_image(rect, filename=image_path)

    # Tạo file PDF trong bộ nhớ
    pdf_buffer = io.BytesIO()
    pdf_document.save(pdf_buffer)
    pdf_document.close()
    
    # Đặt con trỏ về đầu file để có thể đọc được từ đầu
    pdf_buffer.seek(0)
    
    return pdf_buffer  # Trả về file PDF trong bộ nhớ

@login_required(login_url='users:login')
def download_file(request, file_id):
    # Get the file object from the database
    file = get_object_or_404(File, id=file_id)
    key_pair = KeyPair.objects.filter(user=request.user, status='Active').first()
    logger = logging.getLogger('applog')

    # Generate the signature
    signature = gen_sig(key_pair, file)
    logger.info(f'Signature generated (hex): {signature.hex()}')

    image_path = os.path.join(settings.MEDIA_ROOT, 'image.png')
    pdf_buffer = insert_image_in_pdf(file.file_path.path, image_path, 4)

        # Sử dụng PdfReader để đọc từ pdf_buffer thay vì file gốc
        # Sử dụng PdfReader để đọc từ pdf_buffer thay vì file gốc
    pdf_buffer.seek(0)  # Đảm bảo con trỏ ở đầu buffer
    pdf_reader = PdfReader(pdf_buffer)
    pdf_writer = PdfWriter()

    # Thêm tất cả các trang từ pdf_buffer vào pdf_writer
    for page in pdf_reader.pages:
        pdf_writer.add_page(page)

    # Thêm chữ ký vào metadata của PDF
    pdf_writer.add_metadata({
        '/Signature': signature.hex(),  # Lưu chữ ký dưới dạng hexadecimal
    })

    # Tạo một BytesIO buffer cho file PDF đã ký cuối cùng
    signed_pdf_buffer = io.BytesIO()
    pdf_writer.write(signed_pdf_buffer)
    signed_pdf_buffer.seek(0)  # Đưa con trỏ về đầu buffer
    file.status = 'Signed'
    file.save()
    # Trả về file PDF    đã ký dưới dạng phản hồi tải về
    response = FileResponse(signed_pdf_buffer, as_attachment=True, filename=f'signed_{file.file_path.name}')
    return response




@login_required(login_url='users:login')
def upload_and_verify(request):
    if request.method == 'POST':
        verification_code = request.POST.get('verification_code')
        uploaded_file = request.FILES.get('file')
        logger = logging.getLogger('applog')

        if not uploaded_file:
            return render(request, 'files/verify_signature.html', {'error': 'Please upload a file.'})

        # Find the user profile by verification code
        try:
            user_profile = UserProfile.objects.get(verification_code=verification_code)
        except UserProfile.DoesNotExist:
            return render(request, 'files/verify_signature.html', {'error': 'Fial'})

        # Get the active public key
        key_pair = KeyPair.objects.filter(user=user_profile.user, status='Active').first()
        if not key_pair:
            logger.info('No active key pair found')
            return render(request, 'files/verify_signature.html', {'error': 'Signature verification failed'})
        filename = f"{uuid.uuid4().hex}_{uploaded_file.name}"
        fs = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, 'temp_files'))
        unique_filename = fs.save(filename, uploaded_file)
        file_url = fs.url(unique_filename)
        try:
            # Read the uploaded PDF file
            reader = PdfReader(uploaded_file)

            # Extract the signature from the PDF metadata
            signature_hex = reader.metadata.get('/Signature', None)
            if signature_hex is None:
                return render(request, 'files/verify_signature.html', {'error': 'Signature verification failed'})

            # logger.info(f'Extracted signature text from metadata: {signature_hex}')

            # Convert the signature from hex back to bytes
            signature_bytes = bytes.fromhex(signature_hex)

            # Extract content for hash calculation
            content = ''
            for page_num in range(len(reader.pages)-1):  # Exclude last page where the signature is stored
                page = reader.pages[page_num]
                content += page.extract_text() if page.extract_text() else ''

            # Hash the content of the PDF
            content_bytes = content.encode('utf-8')
            hash_value = hashlib.sha256(content_bytes).digest()

            # Log the hash value
            logger.info(f'Hash value (hex): {hash_value.hex()}')

            # Load the public key
            public_key = serialization.load_pem_public_key(
                key_pair.public_key.encode('utf-8'),
                backend=default_backend()
            )

            # Verify the signature
            public_key.verify(
                signature_bytes,  # The signature to be verified
                hash_value,       # The hashed content of the file
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            logger.info('Signature verification succeeded.')
            verification_status = "Signature verification succeeded!"

        except Exception as e:
            logger.error(f'Signature verification failed: {e}')
            verification_status = f"Signature verification failed"

        return render(request, 'files/verify_signature.html', {
            'verification_status': verification_status,
            'user_profile': user_profile  # Adding user_profile to context for display
        })

    return render(request, 'files/verify_signature.html')
