from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from .models import UserProfile

class UserRegisterForm(UserCreationForm):
    email = forms.EmailField(required=True, max_length=255)
    company = forms.CharField(max_length=255, required=True)
    company_abbreviation = forms.CharField(max_length=10, required=True)
    company_address = forms.CharField(widget=forms.Textarea, required=True)
    phone_number = forms.CharField(max_length=20, required=True)
    verification_code = forms.CharField(max_length=255, required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 
                  'company', 'company_abbreviation', 
                  'company_address', 'phone_number', 
                  'verification_code']

    def clean_verification_code(self):
        verification_code = self.cleaned_data.get('verification_code')
        if UserProfile.objects.filter(verification_code=verification_code).exists():
            raise forms.ValidationError("Mã xác nhận này đã tồn tại.")
        return verification_code

    def save(self, commit=True):
        user = super().save(commit=False)
        if commit:
            user.save()
            UserProfile.objects.create(
                user=user,
                company=self.cleaned_data['company'],
                company_abbreviation=self.cleaned_data['company_abbreviation'],
                company_address=self.cleaned_data['company_address'],
                phone_number=self.cleaned_data['phone_number'],
                verification_code=self.cleaned_data['verification_code']
            )
        return user


class UserLoginForm(forms.Form):
    username = forms.CharField(max_length=150, required=True, label='Tên đăng nhập')
    password = forms.CharField(widget=forms.PasswordInput, required=True, label='Mật khẩu')


    def clean_password(self):
        password = self.cleaned_data.get('password')
        # Kiểm tra nếu password là hợp lệ (tùy chọn)
        # Bạn có thể thêm logic để kiểm tra nếu cần
        return password

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['company', 'company_abbreviation', 'company_address', 'phone_number', 'verification_code']
    
    def clean_verification_code(self):
        verification_code = self.cleaned_data.get('verification_code')
        if UserProfile.objects.filter(verification_code=verification_code).exists():
            raise forms.ValidationError("Mã xác nhận này đã tồn tại.")
        return verification_code

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['company'].widget.attrs.update({'placeholder': 'Nhập tên công ty'})
        self.fields['company_abbreviation'].widget.attrs.update({'placeholder': 'Nhập viết tắt công ty'})
        self.fields['company_address'].widget.attrs.update({'placeholder': 'Nhập địa chỉ công ty'})
        self.fields['phone_number'].widget.attrs.update({'placeholder': 'Nhập số điện thoại'})
        self.fields['verification_code'].widget.attrs.update({'placeholder': 'Nhập mã xác nhận'})

class VerificationCodeSearchForm(forms.Form):
    verification_code = forms.CharField(
        max_length=255,
        required=True,
        label='Mã xác nhận',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nhập mã xác nhận'
        })
    )
