from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.UserRegister.as_view(), name='register'),
    path('logout/', views.Logout.as_view(), name='logout'),
    path('login/', views.Login.as_view(), name='login'),
    path('user-update/', views.UserUpdate.as_view(), name='user-update'),
    path('password-change/', views.UserPasswordChange.as_view(), name='password-change'),
    path('', views.Users.as_view(), name='users'),
]
