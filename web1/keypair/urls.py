from django.urls import path
from . import views

urlpatterns = [
     path('expire-keypair/<str:verification_code>/', views.expire_keypair, name='expire_keypair'),
    path('generate-keypair/<str:verification_code>/', views.generate_keypair, name='generate_keypair'),
]
