from django.urls import path
from . import views
from django.conf.urls.static import static
from django.conf import settings
app_name = 'picture'

urlpatterns = [
    path('', views.get_all_pictures, name='get_all_pictures'),  # Lấy tất cả ảnh
    path('create/', views.create_picture, name='create_picture'),  # Tạo ảnh
    path('delete/<int:pk>/', views.delete_picture, name='delete_picture'),  # Xóa ảnh
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)