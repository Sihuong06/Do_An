from django.db import models
from django.contrib.auth.models import User

app_name = 'picture'
class Picture(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='pictures')  # Thêm related_name
    img_path = models.CharField(max_length=255)

    def __str__(self):
        return f"Picture {self.id} for {self.user.username}"

