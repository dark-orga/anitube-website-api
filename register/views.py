# import jwt
# import os

# from django.contrib.auth import logout
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from google.auth.transport import requests
from google.oauth2 import id_token

# from google.auth.oauthlib.id_token import verify_oauth2_token
# from django.http import HttpResponse
# from rest_framework import status
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from rest_framework_simplejwt.tokens import RefreshToken
# from social_core.exceptions import AuthException, MissingBackend
# from social_django.utils import load_backend, load_strategy


# def index(request):
#     return HttpResponse("Hello, world. You're at the register index.")


# class GoogleLoginAPI(APIView):
#     def get(self, request):
#         return Response({"message": "Google login"})
#         strategy = load_strategy(request)
#         backend = load_backend(
#             strategy=strategy,
#             name="google-oauth2",
#             redirect_uri="https://profile.intra.42.fr/users/aanjaimi",
#         )

#         authorization_url = backend.auth_url()
#         return Response({"authorization_url": authorization_url})


# class GoogleCallbackAPI(APIView):
#     def get(self, request):
#         code = request.GET.get("code", None)
#         if code is None:
#             return Response(
#                 {"error": "Code not found"}, status=status.HTTP_400_BAD_REQUEST
#             )

#         try:
#             strategy = load_strategy(request)
#             backend = load_backend(
#                 strategy=strategy,
#                 name="google-oauth2",
#                 redirect_uri="https://profile.intra.42.fr/users/aanjaimi",
#             )

#             # Complete the authentication process
#             user = backend.complete(request=request)

#             # Create JWT tokens
#             refresh = RefreshToken.for_user(user)
#             access_token = str(refresh.access_token)

#             # Return tokens and user data
#             return Response(
#                 {
#                     "access_token": access_token,
#                     "refresh_token": str(refresh),
#                     "user": {
#                         "id": user.id,
#                         "email": user.email,
#                         "name": user.get_full_name(),
#                     },
#                 }
#             )

#         except (MissingBackend, AuthException) as e:
#             return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
def sign_in(request):
    return render(request, "home.html")


@csrf_exempt
def auth_receiver(request):
    """
    Google calls this URL after the user has signed in with their Google account.
    """
    token = request.POST["credential"]

    try:
        user_data = id_token.verify_oauth2_token(
            token,
            requests.Request(),
            "213955431222-n012vqa4sbicq61669v9hk2qphmrildm.apps.googleusercontent.com",
        )
    except ValueError:
        return HttpResponse(status=403)

    # In a real app, I'd also save any new user here to the database.
    request.session["user_data"] = user_data

    return redirect("sign_in")


def sign_out(request):
    del request.session["user_data"]
    return redirect("sign_in")


# add user to database
# from django.http import HttpResponse, HttpRequest
# from django.utils.decorators import method_decorator
# from django.views.decorators.csrf import csrf_exempt
# from rest_framework.views import APIView
# from . import models

# @method_decorator(csrf_exempt, name='dispatch')
# class AuthGoogle(APIView):
#     """
#     Google calls this URL after the user has signed in with their Google account.
#     """
#     def post(self, request, *args, **kwargs):
#         try:
#             user_data = self.get_google_user_data(request)
#         except ValueError:
#             return HttpResponse("Invalid Google token", status=403)

#         email = user_data["email"]
#         user, created = models.User.objects.get_or_create(
#             email=email, defaults={
#                 "username": email, "sign_up_method": "google",
#                 "first_name": user_data.get("given_name"),
#             }
#         )

#         # Add any other logic, such as setting a http only auth cookie as needed here.
#         return HttpResponse(status=200)

#     @staticmethod
#     def get_google_user_data(request: HttpRequest):
#         token = request.POST['credential']
#         return id_token.verify_oauth2_token(
#             token, requests.Request(), os.environ['GOOGLE_OAUTH_CLIENT_ID']
#         )
