import os

import requests
from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from django.shortcuts import HttpResponse, redirect
from django.utils.http import urlencode, urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.encoding import force_str, force_bytes
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
        

        response = JsonResponse({"message": "Login successful"})
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,               # True in production with HTTPS
            samesite="Lax",             # or "None" if frontend/backend are on different domains
            max_age=3600                # 1 hour
        )
        
        response.set_cookie(
            key="refresh_token",
            value=str(refresh),
            httponly=True,
            secure=False,               # True in production with HTTPS
            samesite="Lax",             # or "None" if frontend/backend are on different domains
            max_age=60 * 60 * 24 * 7    # 7 days
        )

        return response


class LogoutAPI(APIView):
    def get(self, request):
        refresh_token = request.COOKIES.get("refresh_token")

        response = JsonResponse({"message": "Logged out"})

        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")

        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception as e:
                pass

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
                response.set_cookie(
                    key="access_token",
                    value=access_token,
                    httponly=True,
                    secure=False,               # True in production with HTTPS
                    samesite="Lax",             # or "None" if frontend/backend are on different domains
                    max_age=3600                # 1 hour
                )
                
                response.set_cookie(
                    key="refresh_token",
                    value=str(refresh),
                    httponly=True,
                    secure=False,               # True in production with HTTPS
                    samesite="Lax",             # or "None" if frontend/backend are on different domains
                    max_age=60 * 60 * 24 * 7    # 7 days
                )
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
        code = request.GET.get("code")
        
        if not code:
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
        if response.status_code != 200:
            return HttpResponse("Failed to get token from Google", status=400)
        
        token_data = response.json()
        if "access_token" not in token_data:
            return HttpResponse("No access token in response", status=400)

        # Use the access token to get user information
        user_info_url = os.getenv("GOOGLE_OAUTH_USER_URL")
        headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        response = requests.get(user_info_url, headers=headers)
        if response.status_code != 200:
            return HttpResponse("Failed to get user info", status=400)

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
            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                secure=False,               # True in production with HTTPS
                samesite="Lax",             # or "None" if frontend/backend are on different domains
                max_age=3600                # 1 hour
            )
            response.set_cookie(
                key="refresh_token",
                value=str(refresh),
                httponly=True,
                secure=False,               # True in production with HTTPS
                samesite="Lax",             # or "None" if frontend/backend are on different domains
                max_age=60 * 60 * 24 * 7    # 7 days
            )
            return response
        else:
            return HttpResponse(
                "Error authenticating user",
                status=status.HTTP_401_UNAUTHORIZED
            )


class RefreshTokenView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh_token")
        if not refresh_token:
            return JsonResponse({"error": "No refresh token"}, status=401)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)

            response = JsonResponse({"message": "Token refreshed"})
            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                secure=False,
                samesite="Lax",
                max_age=3600  # 1 hour
            )
            return response
        except Exception as e:
            return JsonResponse({"error": "Invalid refresh token"}, status=401)


class ForgetPasswordAPI(APIView):
    def get(self, request):
        email = request.data.get('email')
        if email is None:
            return Response({"error": "No email provided"}, status=400)

        user = User.objects.get(email)
        if user is None:
            return Response({"error": "User not found"}, status=400)

        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_url = "http://localhost:3000/reset-password?uid={uid}&token={token}"

        send_mail(
            subject='Reset your password',
            message=f'Click here to reset your password: {reset_url}',
            from_email='anitube-website@gmail.com',
            recipient_list=[email],
        )

        return Response({"message": "A reset link was sent to your email."})

class ResetPasswordAPI(APIView):
    def post(self, request):
        uidb64 = request.data.get("uid")
        token = request.data.get("token")
        new_password = request.data.get("new_password")

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid link"}, status=400)

        if default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return Response({"message": "Password reset successful"})
        else:
            return Response({"error": "Token is invalid or expired"}, status=400)
