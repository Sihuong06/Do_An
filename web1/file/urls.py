from django.urls import path
from . import views

urlpatterns = [
    path('upload/', views.upload_file, name='upload_file'),  # Đường dẫn để tải lên file
    path('file/<int:file_id>/', views.view_file, name='view_file'),  # Xem nội dung file đã upload
    path('files/status/<str:status>/', views.list_files_by_status, name='list_files_by_status'),  # Xem file theo trạng thái (signed, unsigned, tất cả)
    path('download/<int:file_id>/', views.download_file, name='download_file'),  # Tải file về máy
]
