from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='pictures')
    file_path = models.FileField(upload_to='uploads/files/')  # Để upload file
    date_signed = models.DateTimeField(auto_now_add=True, null=True, blank=True)  # Ngày ký file
    status = models.CharField(max_length=20, default='unsigned')

    def __str__(self):
        return f"File {self.id}"