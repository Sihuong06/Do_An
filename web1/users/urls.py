from django.urls import path
from . import views
from .views import LoginAPIView, LogoutAPIView
app_name = 'users'

urlpatterns = [
    path('api/login/', LoginAPIView.as_view(), name='api-login'),  # API đăng nhập
    path('api/logout/', LogoutAPIView.as_view(), name='api-logout'),  # API đăng xuất
    path('register/', views.user_register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('profile/', views.user_update, name='profile'),
    path('all_users/', views.all_users, name='all_users'),
    path('search/', views.search_by_verification_code, name='search_by_verification_code'),  # Thêm dòng này
]
