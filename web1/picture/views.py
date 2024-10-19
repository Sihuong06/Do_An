# views.py
from django.shortcuts import render, redirect, get_object_or_404
from .models import Picture
from .forms import PictureForm
from django.contrib.auth.decorators import login_required

@login_required
def get_all_pictures(request):
    pictures = Picture.objects.all()  # Lấy tất cả ảnh
    return render(request, 'pictures/picture_list.html', {'pictures': pictures})

@login_required
def create_picture(request):
    if request.method == 'POST':
        form = PictureForm(request.POST, request.FILES)  # Nhớ thêm FILES để xử lý ảnh
        if form.is_valid():
            picture = form.save(commit=False)
            picture.user = request.user  # Gán người dùng hiện tại
            picture.save()
            return redirect('picture:get_all_pictures')  # Chuyển hướng về trang danh sách ảnh
    else:
        form = PictureForm()
    return render(request, 'pictures/picture_form.html', {'form': form})

@login_required
def delete_picture(request, pk):
    picture = get_object_or_404(Picture, pk=pk)

    # Kiểm tra xem người dùng có phải là người đã tạo ảnh hay không
    if picture.user == request.user:
        picture.delete()
        return redirect('picture:get_all_pictures')  # Chuyển hướng về trang danh sách ảnh
    else:
        return render(request, 'pictures/picture_list.html', {
            'pictures': Picture.objects.all(),
            'error': 'Bạn không có quyền xóa ảnh này.'
        })
