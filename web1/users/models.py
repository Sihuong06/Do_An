from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    company = models.CharField(max_length=255)  # Tên công ty
    company_abbreviation = models.CharField(max_length=10)  # Viết tắt tên công ty
    company_address = models.TextField()  # Địa chỉ công ty
    phone_number = models.CharField(max_length=20)  # Số điện thoại
    verification_code = models.CharField(max_length=255, unique=True)  # Mã xác nhận

    def __str__(self):
        return f"{self.user.username}'s profile"
