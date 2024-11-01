import os

import requests
from django.contrib.auth import authenticate, login
from django.shortcuts import HttpResponse, redirect
from django.utils.http import urlencode
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User
from .serializers import UserSerializer


class RegisterAPI(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPI(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if email is None or password is None:
            return Response(
                {"error": "Email and password are required!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.filter(email=email).first()

        if user is None:
            return Response(
                {"error": "User not found!"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.check_password(password):
            return Response(
                {"error": "Incorrect password!"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Generate token
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        response = redirect(os.getenv("FRONTEND_ORIGIN_URL"))
        response.set_cookie(
            key="auth_token",
            value=access_token,
            httponly=True
        )

        return response


class Redirect42API(APIView):
    def get(self, request):
        authorization_url = os.getenv("42_OAUTH_AUTHORIZATION_URL")
        params = {
            "client_id": os.getenv("42_OAUTH_CLIENT_ID"),
            "response_type": "code",
            "redirect_uri": os.getenv("42_OAUTH_CALLBACK_URL"),
        }
        return redirect(f"{authorization_url}?{urlencode(params)}")


class Login42API(APIView):
    def get(self, request):
        code = request.GET.get("code")
        if code is None:
            return Response(
                {"error": "Code not provided."},
                status=status.HTTP_400_BAD_REQUEST
            )

        data = {
            "grant_type": "authorization_code",
            "client_id": os.getenv("42_OAUTH_CLIENT_ID"),
            "client_secret": os.getenv("42_OAUTH_CLIENT_SECRET"),
            "redirect_uri": os.getenv("42_OAUTH_CALLBACK_URL"),
            "code": code,
        }

        response = requests.post(os.getenv("42_OAUTH_TOKEN_URL"), data=data)
        response_data = response.json()
        if response.status_code == 200:
            access_token = response_data.get("access_token")
            user_data = requests.get(
                os.getenv("42_OAUTH_USER_URL"),
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_data = user_data.json()

            if "email" not in user_data:
                return HttpResponse("Error getting user information",
                                    status=status.HTTP_400_BAD_REQUEST)

            user_email = user_data["email"]

            # Authenticate or create user based on email
            user = User.objects.filter(email=user_email).first()
            if user is None:
                user = User.objects.create_user(
                        email=user_email, username=user_email
                    )
            authenticated_user = authenticate(request, username=user_email)
            if authenticated_user is not None:
                login(request, authenticated_user)

                # Generate token
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                response = redirect(os.getenv("FRONTEND_ORIGIN_URL"))
                response.set_cookie(key="auth_token",
                                    value=access_token, httponly=True)
                return response
            else:
                return HttpResponse(
                    "Error authenticating user",
                    status=status.HTTP_401_UNAUTHORIZED
                )


class RedirectGoogleAPI(APIView):
    def get(self, request):
        authorization_url = os.getenv("GOOGLE_OAUTH_AUTHORIZATION_URL")
        params = {
            "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/userinfo.email",
            "redirect_uri": os.getenv("GOOGLE_OAUTH_CALLBACK_URL"),
        }
        return redirect(f"{authorization_url}?{urlencode(params)}")


class LoginGoogleAPI(APIView):
    def get(self, request):
        try:
            code = request.GET.get("code")
        except KeyError:
            return HttpResponse("No code provided", status=400)

        # Exchange the code for an access token
        token_url = os.getenv("GOOGLE_OAUTH_TOKEN_URL")
        data = {
            "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
            "code": code,
            "redirect_uri": os.getenv("GOOGLE_OAUTH_CALLBACK_URL"),
            "grant_type": "authorization_code",
        }
        response = requests.post(token_url, data=data)
        token_data = response.json()

        if "access_token" not in token_data:
            return HttpResponse("Error getting access token", status=400)

        # Use the access token to get user information
        user_info_url = os.getenv("GOOGLE_OAUTH_USER_URL")
        headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        response = requests.get(user_info_url, headers=headers)
        user_data = response.json()

        if "email" not in user_data:
            return HttpResponse("Error getting user information", status=400)

        user_email = user_data["email"]

        # Authenticate or create user based on email
        user = User.objects.filter(email=user_email).first()
        if user is None:
            user = User.objects.create_user(
                    email=user_email, username=user_email
                )

        authenticated_user = authenticate(request, username=user_email)
        if authenticated_user is not None:
            login(request, authenticated_user)

            # Generate token
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            response = redirect(os.getenv("FRONTEND_ORIGIN_URL"))
            response.set_cookie(key="auth_token",
                                value=access_token, httponly=True)
            return response
        else:
            return HttpResponse(
                "Error authenticating user",
                status=status.HTTP_401_UNAUTHORIZED
            )
