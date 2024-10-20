from django.shortcuts import render, redirect, get_object_or_404
from django.core.files.storage import FileSystemStorage
from .models import File
from keypair.models import KeyPair
from .forms import FileUploadForm  # Tạo form upload file
from django.http import HttpResponse
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
from django.http import FileResponse


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




def download_file(request, file_id):
    file = get_object_or_404(File, id=file_id)
    key_pair = KeyPair.objects.filter(user=request.user, status='Active').first()
    logger = logging.getLogger('applog')
    private_key_data = key_pair.private_key  # Assuming this is the PEM-encoded key stored in a string
    private_key = serialization.load_pem_private_key(
        private_key_data.encode('utf-8'),  # Ensure the key is loaded as bytes
        password=None,  # Add a password if your private key is encrypted
        backend=default_backend()
    )
    reader = PdfReader(file.file_path)
    content = ''
    for page_num in range(len(reader.pages)):
        page = reader.pages[page_num]
        content += page.extract_text() 
    content_bytes = content.encode('utf-8') 
    hash_value = hashlib.sha256(content_bytes).digest()
    # logger.info(hash_value)

    signature = private_key.sign(
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    logger.info(signature.hex())
    return render(request, 'files/file_detail.html')

# @login_required(login_url='users:login')
# def download_file(request, file_id):
#     file = get_object_or_404(File, id=file_id)
#     key_pair = KeyPair.objects.filter(user=request.user, status='Active').first()
#     logger = logging.getLogger('applog')
#     if key_pair:
#         logger.info('Key pair found')
#     else:
#         logger.error('No active key pair found')
#     #     private_key = key_pair.private_key  # Ensure this is an appropriate object type
#     #     content = file.file_path.read()  # Read the content of the PDF file

#     #     # Calculate the hash of the content
#     #     hash_value = hashlib.sha256(content).digest()

#     #     # Sign the hash with the private key
#     #     signature = private_key.sign(
#     #         hash_value,
#     #         padding.PSS(
#     #             mgf=padding.MGF1(hashes.SHA256()),
#     #             salt_length=padding.PSS.MAX_LENGTH
#     #         ),
#     #         hashes.SHA256()
#     #     )
#     #     print(signature.hex())
#     #     # Prepare the PDF for signing
#     #     pdf_writer = PdfWriter()
#     #     pdf_reader = PdfReader(file.file_path.path)

#     #     # Add all pages to the writer
#     #     for page in pdf_reader.pages:
#     #         pdf_writer.add_page(page)

#     #     # Create a new page for the signature or overlay text
#     #     signature_page = pdf_writer.add_blank_page(width=pdf_reader.pages[0].width, height=pdf_reader.pages[0].height)

#     #     # Insert the signature on the new page (example: writing binary signature)
#     #     # Note: You might want to customize the position and format
#     #     signature_text = f"Signature: {signature.hex()}"
#     #     signature_page.insert_text(signature_text, 100, 100)  # Example coordinates (x, y)

#     #     # Create a temporary file to save the signed PDF
#     #     signed_pdf_path = 'path/to/temp_signed_file.pdf'
#     #     with open(signed_pdf_path, 'wb') as signed_pdf_file:
#     #         pdf_writer.write(signed_pdf_file)

#     #     # Return the signed PDF for download
#     #     response = FileResponse(open(signed_pdf_path, 'rb'), as_attachment=True, filename='signed_' + file.file_path.name)
#     #     return response

#     return render(request, 'files/file_detail.html', {'file': file})
