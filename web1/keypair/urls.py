from django.urls import path
from . import views

app_name = 'keypair'

urlpatterns = [
    path('generate-keypair/', views.generate_keypair, name='generate_keypair'),
    path('expire-keypair/', views.expire_keypair, name='expire_keypair'),
]
