from django.db import models
from django.contrib.auth.models import User


class Picture(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='pictures')
    img_path = models.ImageField(upload_to='pictures/')  # Thay đổi thành ImageField để upload ảnh

    def __str__(self):
        return f"Picture {self.id} for {self.user.username}"
