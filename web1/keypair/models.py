from django.db import models
from django.contrib.auth.models import User

class KeyPair(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='keypairs')
    public_key = models.TextField()
    private_key = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    expire = models.DateTimeField()  # New expire field
    status = models.CharField(max_length=10, choices=[('Active', 'Active'), ('Expired', 'Expired')])

    def __str__(self):
        return f'KeyPair for {self.user.user.username} ({self.status})'

