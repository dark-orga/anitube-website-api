from django.urls import path

from .views import GoogleCallbackAPI, GoogleLoginAPI

urlpatterns = [
    path("auth/google/", GoogleLoginAPI.as_view(), name="google-login"),
    path("auth/google/callback/", GoogleCallbackAPI.as_view(), name="google-callback"),
]
