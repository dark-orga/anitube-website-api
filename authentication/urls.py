from django.urls import path

from .views import (Login42API, LoginAPI, LoginGoogleAPI, Redirect42API,
                    RedirectGoogleAPI, RegisterAPI)

urlpatterns = [
    # crendentials auth
    path("register", RegisterAPI.as_view(), name="register"),
    path("login", LoginAPI.as_view(), name="login"),
    # 42 auth
    path("auth/42/", Redirect42API.as_view(), name="login-42"),
    path("auth/42/callback", Login42API.as_view(), name="42"),
    # Google auth
    path("auth/google", RedirectGoogleAPI.as_view(), name="auth_receiver"),
    path("auth/google/callback", LoginGoogleAPI.as_view(), name="google"),
]
