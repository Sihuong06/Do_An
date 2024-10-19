from django import forms
from .models import Picture

class PictureForm(forms.ModelForm):
    class Meta:
        model = Picture
        fields = ['img_path']  # Chỉ cần trường upload ảnh
