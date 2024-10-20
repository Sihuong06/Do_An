from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class File(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='files')  # Thêm related_name
    file_path = models.FileField(upload_to='uploads/')
    date_signed = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20)

    def __str__(self):
        return f"File {self.id} - {self.status} by {self.user.username}"
