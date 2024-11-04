from django.urls import path
from . import views
from django.conf.urls.static import static
from django.conf import settings

app_name = 'file'
urlpatterns = [
    path('upload/', views.upload_file, name='upload_file'),  # Đường dẫn để tải lên file
    path('<int:file_id>/', views.view_file, name='view_file'),  # Xem nội dung file đã upload
    path('', views.list_files, name='list_files'),
    path('download/<int:file_id>/', views.download_file, name='download_file'),  # Tải file về máy
    path('upload-verify/', views.upload_and_verify, name='upload_verify'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
