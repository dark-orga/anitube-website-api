from django.urls import path

# from .views import GoogleLoginAPI, GoogleCallbackAPI
from . import views

urlpatterns = [
    # path("", index, name="index"),
    # path("", views.index, name="index"),
    # path("logout", views.logout, name="logout"),
    # path("google/", GoogleLoginAPI.as_view(), name="google-login"),
    # path("google/callback/", GoogleCallbackAPI.as_view(), name="google-callback"),
    path("", views.sign_in, name="sign_in"),
    path("sign-out/", views.sign_out, name="sign_out"),
    path("auth-receiver/", views.auth_receiver, name="auth_receiver"),
]
