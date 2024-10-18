
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from google.auth.transport import requests
from google.oauth2 import id_token
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from social_core.exceptions import AuthException, MissingBackend
from social_django.utils import load_backend, load_strategy
from .serializers import UserSerializer
import jwt, datetime, os, requests
from .models import User
from rest_framework.exceptions import AuthenticationFailed



class RegisterAPI(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class LoginAPI(APIView):
    def post(self, request):
        print(request.data)
        email = request.data['email']
        password = request.data['password']

        # user = authenticate(email=email, password=password)
        user = User.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'username': user.username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')

        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            'jwt': token
        }

        return Response(UserSerializer(user).data, status=status.HTTP_200_OK)

class Login42API(APIView):
    def post(self, request):
        code = request.data.get('code')
        if not code:
            return Response({'error': 'Code not provided.'}, status=status.HTTP_400_BAD_REQUEST)

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
                    return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            else:
                return Response(response_data, status=response.status_code)
        
        except requests.exceptions.RequestException as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    