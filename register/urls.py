from django.urls import path
from .views import RegisterAPI, LoginAPI, Login42API

urlpatterns = [
    # crendentials auth
    path("register/", RegisterAPI.as_view(), name="register"),
    path("login/", LoginAPI.as_view(), name="login"),
    
    # 42 auth
    path("login/42/", Login42API.as_view(), name="login-42"),   
]
