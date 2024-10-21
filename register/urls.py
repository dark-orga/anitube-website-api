from django.urls import path

from .views import (Login42API, LoginAPI, LoginGoogleAPI, RedirectGoogleAPI,
                    RegisterAPI)

urlpatterns = [
    # crendentials auth
    path("register/", RegisterAPI.as_view(), name="register"),
    path("login/", LoginAPI.as_view(), name="login"),
    # 42 auth
    path("login/42/", Login42API.as_view(), name="login-42"),
    # Google auth
    path("login/google/callback", LoginGoogleAPI.as_view(), name="google"),
    path("login/google", RedirectGoogleAPI.as_view(), name="auth_receiver"),
]
