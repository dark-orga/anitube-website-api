import datetime
import os

import jwt
import requests
from django.contrib.auth import authenticate, login
from django.shortcuts import HttpResponse, redirect
# from google.auth.transport import requests
from django.utils.http import urlencode
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import APIView

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
        email = request.data["email"]
        password = request.data["password"]

        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed("User not found!")

        if not user.check_password(password):
            raise AuthenticationFailed("Incorrect password!")

        payload = {
            "id": user.id,
            "username": user.username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            "iat": datetime.datetime.utcnow(),
        }

        token = jwt.encode(payload, "secret", algorithm="HS256")

        response = Response()

        response.set_cookie(key="jwt", value=token, httponly=True)
        response.data = {"jwt": token}

        return Response(UserSerializer(user).data, status=status.HTTP_200_OK)


class Login42API(APIView):
    def post(self, request):
        code = request.data.get("code")
        if not code:
            return Response(
                {"error": "Code not provided."}, status=status.HTTP_400_BAD_REQUEST
            )

        data = {
            "grant_type": "authorization_code",
            "client_id": os.getenv("SOCIAL_AUTH_FORTYTWO_KEY"),
            "client_secret": os.getenv("SOCIAL_AUTH_FORTYTWO_SECRET"),
            "redirect_uri": "http://localhost:3000/",
            "code": code,
        }

        try:
            response = requests.post("https://api.intra.42.fr/oauth/token/", data=data)
            response_data = response.json()

            if response.status_code == 200:
                access_token = response_data.get("access_token")
                try:
                    user_data = requests.get(
                        "https://api.intra.42.fr/v2/me",
                        headers={"Authorization": f"Bearer {access_token}"},
                    )
                    user_data = user_data.json()

                    return Response(user_data, status=status.HTTP_200_OK)

                except requests.exceptions.RequestException as e:
                    return Response(
                        {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

            else:
                return Response(response_data, status=response.status_code)

        except requests.exceptions.RequestException as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RedirectGoogleAPI(APIView):
    def get(self, request):
        authorization_url = "https://accounts.google.com/o/oauth2/v2/auth"
        params = {
            "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/userinfo.email",
            "redirect_uri": "http://localhost:8000/api/login/google/callback",
        }
        return redirect(f"{authorization_url}?{urlencode(params)}")


class LoginGoogleAPI(APIView):
    def get(self, request):
        try:
            code = request.GET.get("code")
        except KeyError:
            return HttpResponse("No code provided", status=400)

        # Exchange the code for an access token
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
            "code": code,
            "redirect_uri": "http://localhost:8000/api/login/google/callback",
            "grant_type": "authorization_code",
        }
        response = requests.post(token_url, data=data)
        token_data = response.json()

        if "access_token" not in token_data:
            return HttpResponse("Error getting access token", status=400)

        # Use the access token to get user information
        user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        response = requests.get(user_info_url, headers=headers)
        user_data = response.json()

        if "email" not in user_data:
            return HttpResponse("Error getting user information", status=400)

        user_email = user_data["email"]

        # Authenticate or create user based on email
        user = User.objects.filter(email=user_email).first()
        if user is not None:
            authenticated_user = authenticate(request, username=user_email)
            if authenticated_user is not None:
                login(request, authenticated_user)
                token, created = Token.objects.get_or_create(user=authenticated_user)
                response_data = {"token": token.key, "email": authenticated_user.email}
                # Construct redirect URL with encoded token
                frontend_url = f"http://localhost:3000/?token={token.key}"
                return redirect(frontend_url)
            else:
                return HttpResponse("Error authenticating user", status=401)
        else:
            try:
                user = User.objects.create_user(email=user_email, username=user_email)
                authenticated_user = authenticate(request, username=user_email)
                if authenticated_user is not None:
                    login(request, authenticated_user)
                    token, created = Token.objects.get_or_create(
                        user=authenticated_user
                    )
                    response_data = {
                        "token": token.key,
                        "email": authenticated_user.email,
                    }
                    frontend_url = f"http://localhost:3000/?token={response_data}"
                    return redirect(frontend_url)
                else:
                    return HttpResponse("Error authenticating the new user", status=401)
            except Exception as e:
                return HttpResponse(str(e), status=500)
        # Redirect to a success page or potentially request additional user info
        return redirect("http://localhost:3000/")

    def handle_exception(self, exc):
        # Log the exception for debugging
        print(f"An error occurred: {str(exc)}")
        # You might want to add more sophisticated logging here

        # Return a user-friendly error response
        return Response(
            {"error": "An error occurred during the login process. Please try again."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# @csrf_exempt
# def sign_in(request):
#     return render(request, "home.html")


# @csrf_exempt
# def auth_receiver(request):
#     """
#     Google calls this URL after the user has signed in with their Google account.
#     """
#     token = request.POST["credential"]
#     try:
#         user_data = id_token.verify_oauth2_token(
#             token,
#             requests.Request(),
#             os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
#         )
#     except ValueError:
#         return HttpResponse(status=403)

#     # In a real app, I'd also save any new user here to the database.
#     request.session["user_data"] = user_data
#     return redirect("sign_in")


# def sign_out(request):
#     del request.session["user_data"]
#     return redirect("sign_in")
