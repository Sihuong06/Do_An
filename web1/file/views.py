from django.shortcuts import render, redirect, get_object_or_404
from django.core.files.storage import FileSystemStorage
from .models import File
from reportlab.lib.pagesizes import letter
from keypair.models import KeyPair
from users.models import UserProfile
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
            uploaded_file.status = 'unsigned' 
            uploaded_file.save()
            # Hiển thị nội dung file sau khi upload
            # file_content = uploaded_file.file_path.read()  # Hiển thị nội dung dạng text

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
    logger = logging.getLogger('applog')
    if key_pair:
        logger.info('Key pair found')
    else:
        logger.error('No active key pair found')
    # Render trang HTML tùy chỉnh và truyền file URL vào template
    return render(request, 'files/file_detail.html', {'file_url': file_url, 'file_obj': file_obj})
    
@login_required(login_url='users:login')
def list_files_by_status(request, status):
    if status == 'all':
        files = File.objects.all()
    else:
        files = File.objects.filter(status=status)
    return render(request, 'files/file_list.html', {'files': files, 'status': status})



# # @login_required(login_url='users:login')
# # def download_file(request, file_id):
#     # Get the file object or return a 404 error
#     file = get_object_or_404(File, id=file_id)

#     # Retrieve the active key pair for the user
#     key_pair = KeyPair.objects.filter(user=request.user, status='Active').first()
    
#     logger = logging.getLogger('applog')
    
#     # Check if the key pair exists
#     if key_pair:
#         logger.info('Key pair found')
        
#         try:
#             # Load the private key from the PEM-encoded string
#             private_key = serialization.load_pem_private_key(
#                 key_pair.private_key.encode('utf-8'),
#                 password=None,
#                 backend=default_backend()
#             )

#             # Read the PDF file
#             reader = PdfReader(file.file_path)
#             content = ''
#             for page_num in range(len(reader.pages)):
#                 page = reader.pages[page_num]
#                 content += page.extract_text() if page.extract_text() else ''
            
#             # Create a hash of the PDF content
#             content_bytes = content.encode('utf-8')
#             hash_value = hashlib.sha256(content_bytes).digest()
#             logger.info(f'Hash value: {hash_value.hex()}')

#             # Generate the signature
#             signature = private_key.sign(
#                 hash_value,
#                 padding.PSS(
#                     mgf=padding.MGF1(hashes.SHA256()),
#                     salt_length=padding.PSS.MAX_LENGTH
#                 ),
#                 hashes.SHA256()
#             )
#             logger.info(f'Signature: {signature}')

#             # Optionally, save the signature or do something with it
#             # file.signature = signature  # If you have a field for signature
#             # file.save()

#         except Exception as e:
#             logger.error(f'Error generating signature: {e}')
#             return HttpResponse("Error generating signature.", status=500)

#         # Render the file detail page with relevant information
#         return render(request, 'files/file_detail.html', {
#             'file': file,
#             'signature': signature.hex()  # Pass the signature to the template if needed
#         })
#     else:
#         logger.error('No active key pair found')
#         return HttpResponse("No active key pair found.", status=403)

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
    for page_num in range(len(reader.pages)):
        page = reader.pages[page_num]
        content += page.extract_text() if page.extract_text() else ''
    
    # Create a hash of the PDF content
    content_bytes = content.encode('utf-8')
    hash_value = hashlib.sha256(content_bytes).digest()

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


@login_required(login_url='users:login')
def download_file(request, file_id):
    # Get the file object from the database
    file = get_object_or_404(File, id=file_id)
    key_pair = KeyPair.objects.filter(user=request.user, status='Active').first()
    logger = logging.getLogger('applog')

    # Generate the signature
    signature = gen_sig(key_pair, file)
    logger.info(f'Signature generated (hex): {signature.hex()}')

    # Open the original PDF file
    pdf_reader = PdfReader(file.file_path.path)
    pdf_writer = PdfWriter()

    # Add all the original pages to the writer
    for page in pdf_reader.pages:
        pdf_writer.add_page(page)

    # Create a BytesIO buffer for the signature page
    signature_buffer = io.BytesIO()
    c = canvas.Canvas(signature_buffer, pagesize=letter)

    # Prepare the signature text
    text = f"{signature.hex()}"

    # Split the signature into multiple lines if it's too long
    line_length = 64  # Maximum length of each line
    lines = [text[i:i + line_length] for i in range(0, len(text), line_length)]

    # Write the lines into the PDF
    for i, line in enumerate(lines):
        c.drawString(100, 750 - (i * 15), line)  # Adjust vertical position for each line

    c.showPage()
    c.save()
    signature_buffer.seek(0)  # Rewind the buffer to the beginning

    # Create a PdfReader for the signature page
    signature_pdf_reader = PdfReader(signature_buffer)
    signature_page = signature_pdf_reader.pages[0]
    pdf_writer.add_page(signature_page)

    # Create a BytesIO buffer for the final signed PDF
    signed_pdf_buffer = io.BytesIO()
    pdf_writer.write(signed_pdf_buffer)
    signed_pdf_buffer.seek(0)  # Rewind the buffer to the beginning

    # Serve the new PDF as a download response
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
            return render(request, 'files/verify_signature.html', {'error': 'No user found for this verification code.'})

        # Get the active public key
        key_pair = KeyPair.objects.filter(user=user_profile.user, status='Active').first()
        if not key_pair:
            logger.info('No active key pair found')
            return render(request, 'files/verify_signature.html', {'error': 'No active key pair found.'})

        try:
            # Read the uploaded PDF file
            reader = PdfReader(uploaded_file)
            content = ''

            # Extract the content of all pages except the last one (assuming signature is on the last page)
            for page_num in range(len(reader.pages) - 1):
                page = reader.pages[page_num]
                content += page.extract_text() if page.extract_text() else ''

            # Hash the content of the PDF
            content_bytes = content.encode('utf-8')
            hash_value = hashlib.sha256(content_bytes).digest()

            # Log the hash value
            logger.info(f'Hash value (hex): {hash_value.hex()}')

            # Extract the signature from the last page of the PDF
            signature_text = reader.pages[-1].extract_text()
            logger.info(f'Extracted signature text: {signature_text}')

            # Clean up the extracted signature (removing newlines and extra spaces)
            signature_hex = signature_text.replace('\n', '').strip()
            logger.info(f'Cleaned signature (hex): {signature_hex}')

            # Convert the signature from hex back to bytes
            signature_bytes = bytes.fromhex(signature_hex)

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
            # logger.error(f'Signature verification failed: {e}')
            verification_status = f"Signature verification failed"

        return render(request, 'files/verify_signature.html', {
            'verification_status': verification_status
        })

    return render(request, 'files/verify_signature.html')
