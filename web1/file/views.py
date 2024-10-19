from django.shortcuts import render, redirect, get_object_or_404
from django.core.files.storage import FileSystemStorage
from .models import File
from .forms import FileUploadForm  # Tạo form upload file
from django.http import HttpResponse

# Upload file và hiển thị nội dung
def upload_file(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.save(commit=False)
            uploaded_file.user = request.user
            uploaded_file.save()
            # Hiển thị nội dung file sau khi upload
            file_content = uploaded_file.file_path.read().decode('utf-8')  # Hiển thị nội dung dạng text
            return render(request, 'files/file_detail.html', {'file': uploaded_file, 'content': file_content})
    else:
        form = FileUploadForm()
    return render(request, 'files/upload_file.html', {'form': form})

def view_file(request, file_id):
    file = get_object_or_404(File, id=file_id)
    # Đọc nội dung file
    file_content = file.file_path.read().decode('utf-8')  # Hiển thị nội dung dạng text
    return render(request, 'files/file_detail.html', {'file': file, 'content': file_content})

def list_files_by_status(request, status):
    if status == 'all':
        files = File.objects.all()
    else:
        files = File.objects.filter(status=status)
    return render(request, 'files/file_list.html', {'files': files, 'status': status})

from django.http import FileResponse

def download_file(request, file_id):
    file = get_object_or_404(File, id=file_id)
    response = FileResponse(file.file_path.open(), as_attachment=True, filename=file.file_path.name)
    return response
