from django.db import models
from django.contrib.auth.models import User

# Create your models here.
import os

class File(models.Model):
    STATUS_CHOICES = [
        ('Unsigned', 'Unsigned'),
        ('Signed', 'Signed'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='files')
    file_name = models.CharField(max_length=500)
    file_path = models.FileField(upload_to='uploads/')
    date_signed = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Unsigned')

    def __str__(self):
        return f"File {self.id} - {self.status} by {self.user.username}"

    def save(self, *args, **kwargs):
        if not self.id:  # Only check for duplicate names when creating a new instance
            original_file_name = self.file_name
            count = 1

            # Tìm phần mở rộng (nếu có) của file
            base_name, extension = os.path.splitext(self.file_name)

            # Check if a file with the same name already exists
            while File.objects.filter(file_name=self.file_name, user=self.user).exists():
                # Thêm số vào cuối tên tệp nếu nó trùng
                self.file_name = f"{base_name}_{count}{extension}"
                count += 1

        super(File, self).save(*args, **kwargs)

