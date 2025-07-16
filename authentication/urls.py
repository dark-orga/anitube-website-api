from django.urls import path

from .views import (Login42API, LoginAPI, LogoutAPI, LoginGoogleAPI, Redirect42API,
                    RedirectGoogleAPI, RegisterAPI, RefreshTokenView,
                    ForgetPasswordAPI, ResetPasswordAPI)

urlpatterns = [
    # crendentials auth
    path("register", RegisterAPI.as_view(), name="register"),
    path("login", LoginAPI.as_view(), name="login"),
    path("logout", LogoutAPI.as_view(), name="logout"),
    # password
    path("forget-password", ForgetPasswordAPI.as_view(), name="forget-password"),
    path("reset-password", ResetPasswordAPI.as_view(), name="reset-password"),
    # tokens
    path("refresh", RefreshTokenView.as_view(), name="refresh"),
    # 42 auth
    path("42/", Redirect42API.as_view(), name="login-42"),
    path("42/callback", Login42API.as_view(), name="42"),
    # Google auth
    path("google", RedirectGoogleAPI.as_view(), name="auth_receiver"),
    path("google/callback", LoginGoogleAPI.as_view(), name="google"),
]
