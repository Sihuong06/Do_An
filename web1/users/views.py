from .models import UserProfile
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import UserRegisterForm, UserLoginForm,UserProfileForm , VerificationCodeSearchForm
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login,logout
from django.contrib.auth.decorators import login_required, user_passes_test


User = get_user_model()

def user_register(request):
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            verification_code = form.cleaned_data['verification_code']
            
            # Kiểm tra xem username đã tồn tại hay chưa
            if User.objects.filter(username=username).exists():
                messages.error(request, "Tên đăng nhập đã tồn tại.")
                return render(request, 'users/register.html', {'form': form})

            # Kiểm tra xem verification_code đã tồn tại hay chưa
            if UserProfile.objects.filter(verification_code=verification_code).exists():
                messages.error(request, "Mã xác nhận đã tồn tại.")
                return render(request, 'users/register.html', {'form': form})

            # Nếu không có lỗi, lưu người dùng
            form.save()
            messages.success(request, "Đăng ký thành công! Bạn có thể đăng nhập ngay.")
            return redirect('users:login')
    else:
        form = UserRegisterForm()

    return render(request, 'users/register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home:home')  # Chuyển hướng đến trang hồ sơ người dùng
            else:
                messages.error(request, 'Tài khoản hoặc mật khẩu không đúng.')
    else:
        form = UserLoginForm()
    return render(request, 'users/login.html', {'form': form})

@login_required(login_url='users:login')
def user_logout(request):
    logout(request)
    return redirect('home:home')

@login_required(login_url='users:login')
def user_update(request):
    profile = request.user.profile  # Lấy thông tin hồ sơ của người dùng
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()  # Lưu thông tin đã cập nhật
            return redirect('users:profile')  # Chuyển hướng đến trang hồ sơ
    else:
        form = UserProfileForm(instance=profile)  # Hiển thị thông tin hiện tại
    
    return render(request, 'users/profile_update.html', {'form': form})

@login_required(login_url='users:login')
def search_by_verification_code(request):
    form = VerificationCodeSearchForm(request.GET or None)
    user_profile = None
    if request.method == 'GET' and form.is_valid():
        verification_code = form.cleaned_data['verification_code']
        user_profile = UserProfile.objects.filter(verification_code=verification_code).first()
        
        if not user_profile:
            return render(request, 'users/search.html', {'form': form, 'error': 'Không tìm thấy hồ sơ nào với mã xác nhận này.'})
    
    return render(request, 'users/search.html', {'form': form, 'user_profile': user_profile})


@login_required(login_url='users:login')
@user_passes_test(lambda user: user.is_superuser)
def all_users(request):
    user_profiles = UserProfile.objects.all()
    return render(request, 'users/all_users.html', {'user_profiles': user_profiles})