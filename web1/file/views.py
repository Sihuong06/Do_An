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
from PIL import Image, ImageDraw, ImageFont
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
import base64
import uuid
from django.core.files.storage import FileSystemStorage
from django.conf import settings
from PIL import Image, ImageDraw, ImageFont
import fitz
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from .signature_utils import sign_rsa, verify_rsa, sign_dsa, verify_dsa, sign_ecdsa, verify_ecdsa, sign_eddsa, verify_eddsa 
from datetime import datetime

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
            uploaded_file.file_name = uploaded_file.file_path.name
            uploaded_file.save()
            file_obj = get_object_or_404(File, id=uploaded_file.id)
            file_url = file_obj.file_path.url
            return render(request, 'files/file_detail.html', {'file_url': file_url, 'file_obj': file_obj})
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



def text_to_image(text, font_size=13, image_size=(250, 100), background_color=(255, 255, 255), text_color=(0, 0, 139), border_color=(0, 128, 0), border_width=3):
    # Tạo ảnh với kích thước và màu nền yêu cầu
    img = Image.new("RGB", image_size, background_color)
    draw = ImageDraw.Draw(img)

    # Tải font chữ
    font = ImageFont.truetype("times.ttf", font_size)

    # Tính toán vị trí của văn bản để căn lề trái và ở giữa theo chiều dọc
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_height = text_bbox[3] - text_bbox[1]
    text_x = 0  # Đặt x = 0 để căn sát mép bên trái
    text_y = (image_size[1] - text_height) // 2  # Căn giữa theo chiều dọc

    # Thêm viền màu xanh lá cây xung quanh hình ảnh
    bordered_img = Image.new("RGB", (image_size[0] + 2 * border_width, image_size[1] + 2 * border_width), border_color)
    bordered_img.paste(img, (border_width, border_width))

    # Vẽ văn bản với màu chữ dark blue vào ảnh
    draw = ImageDraw.Draw(bordered_img)
    draw.multiline_text((text_x + border_width, text_y + border_width), text, fill=text_color, font=font, align="left")
    # Thêm dấu tick xanh lá cây đậm và mờ
    tick_color = (0, 128, 0, 150)  # Xanh lá cây đậm với độ mờ alpha = 150
    tick_layer = Image.new("RGBA", bordered_img.size, (255, 255, 255, 0))  # Tạo layer trong suốt
    tick_draw = ImageDraw.Draw(tick_layer)

    # Vẽ dấu tick hình chữ V
    tick_coords = [(150, 80), (170, 100), (210, 60)]  # Tọa độ cho hình tick
    tick_draw.line(tick_coords, fill=tick_color, width=10)

    # Ghép layer chứa dấu tick lên ảnh chính
    bordered_img = Image.alpha_composite(bordered_img.convert("RGBA"), tick_layer)
    # Hiển thị hoặc lưu ảnh
    bordered_img.save("F:/Do_An/web1/media/image.png")  # Để lưu ảnh
    # bordered_img.show()  # Để hiển thị ảnh
    # bordered_img.save("output_image.png")  # Để lưu ảnh

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

def get_content_file(file):
    reader = PdfReader(file.file_path)
    content = ''
    for page_num in range(len(reader.pages)-1):
        page = reader.pages[page_num]
        content += page.extract_text() if page.extract_text() else ''
    content_bytes = content.encode('utf-8')
    hash_value = hashlib.sha256(content_bytes).digest()
    return hash_value


def gen_sig(keypair,hash_value):
    if keypair.type=='RSA':
        return sign_rsa(keypair,hash_value)
    elif keypair.type=='DSA':
        return sign_dsa(keypair,hash_value)
    elif keypair.type=='ECDSA':
        return sign_ecdsa(keypair,hash_value)
    elif keypair.type=='Ed25519':
        return sign_eddsa(keypair,hash_value)
    # Load the private key from the PEM-encoded string
def verify(keypair, hash_value, signature):
    if keypair.type == 'RSA':
        return verify_rsa(keypair, hash_value, signature)
    elif keypair.type == 'DSA':
        return verify_dsa(keypair, hash_value, signature)
    elif keypair.type == 'ECDSA':   
        return verify_ecdsa(keypair, hash_value, signature)
    elif keypair.type == 'Ed25519':
        return verify_eddsa(keypair, hash_value, signature)

@login_required(login_url='users:login')
def download_file(request, file_id):
    # Get the file object from the database
    file = get_object_or_404(File, id=file_id)
    key_pair = KeyPair.objects.filter(user=request.user, status='Active').first()
    logger = logging.getLogger('applog')
    hash_value = get_content_file(file)
    logger.info(f'type hash_value: {type(hash_value)}')
    # Generate the signature
    logger.info(f"type keypair private key: {type(key_pair.private_key)}")
    signature = gen_sig(key_pair, hash_value)
    logger.info(f'signature type: {type(signature)}')
    logger.info(f'signature: {signature}')
     
    # Lấy thông tin từ người dùng và ngày hiện tại
    user_full_name = f"{request.user.username}"
    current_date = datetime.now().strftime('%d/%m/%Y')

    # Tạo đoạn văn bản cần chuyển đổi
    text = f"""Signature Valid:
    Ký bởi(Signed By): {user_full_name}
    Ký ngày(Signing Date): {current_date}"""

    # Gọi hàm để chuyển đổi text thành ảnh
    text_to_image(
        text,
        background_color=(220, 255, 220)  # Xanh lá cực nhạt
    )
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
    # if key_pair.type != 'EdDSA':
    pdf_writer.add_metadata({
        '/Signature': signature.hex()  # Store signature as hexadecimal
    })
    # else:
    #     pdf_writer.add_metadata({
    #         '/Signature': signature  # Store signature as base64
    #     })

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
            return render(request, 'files/verify_signature.html', {
                'error': 'Please upload a file.',
                'verification_code': verification_code
            })

        # Attempt to find the user profile by verification code
        try:
            user_profile = UserProfile.objects.get(verification_code=verification_code)
        except UserProfile.DoesNotExist:
            return render(request, 'files/verify_signature.html', {
                'error': 'Invalid verification code',
                'verification_code': verification_code
            })

        # Retrieve the active public key for the user
        key_pair = KeyPair.objects.filter(user=user_profile.user, status='Active').first()
        if not key_pair:
            logger.info('No active key pair found')
            return render(request, 'files/verify_signature.html', {
                'error': 'Văn Bản Không Hợp Lệ',
                'verification_code': verification_code,
                'uploaded_file_name': uploaded_file.name
            })

        # Save the uploaded file temporarily
        filename = f"{uuid.uuid4().hex}_{uploaded_file.name}"
        fs = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, 'temp_files'))
        unique_filename = fs.save(filename, uploaded_file)
        file_url = fs.url(unique_filename)

        try:
            # Read the uploaded PDF file
            reader = PdfReader(uploaded_file)
            signature_hex = reader.metadata.get('/Signature', None)
            if signature_hex is None:
                return render(request, 'files/verify_signature.html', {
                    'error': 'Văn Bản Không Hợp Lệ',
                    'verification_code': verification_code,
                    'uploaded_file_name': uploaded_file.name
                })

            # Convert the signature from hex back to bytes
            if key_pair.type != 'EdDSA':
                signature_hex = bytes.fromhex(signature_hex)
                
            # Extract and hash the PDF content (excluding the last page where signature is stored)
            content = ''
            for page_num in range(len(reader.pages) - 1):
                page = reader.pages[page_num]
                content += page.extract_text() if page.extract_text() else ''

            content_bytes = content.encode('utf-8')
            hash_value = hashlib.sha256(content_bytes).digest()
            logger.info(f'Hash value (hex): {hash_value.hex()}')

            # Load and use the public key for verification
            if (verify(key_pair, hash_value, signature_hex)):
                logger.info('Signature verification succeeded.')
                verification_status = "Văn Bản Hợp Lệ"
            else:
                logger.error('Signature verification failed.')
                verification_status = "Văn Bản Không Hợp Lệ"

        except Exception as e:
            logger.error(f'Văn Bản Không Hợp Lệ: {e}')
            verification_status = "Văn Bản Không Hợp Lệ"

        # Return the response with verification status and retained values
        return render(request, 'files/verify_signature.html', {
            'verification_status': verification_status,
            'user_profile': user_profile,
            'verification_code': verification_code,
            'uploaded_file_name': uploaded_file.name
        })

    return render(request, 'files/verify_signature.html')