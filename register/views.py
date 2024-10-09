# import jwt
# from django.shortcuts import redirect
# from django.http import HttpResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from social_core.exceptions import AuthException, MissingBackend
from social_django.utils import load_backend, load_strategy


class GoogleLoginAPI(APIView):
    def get(self, request):
        strategy = load_strategy(request)
        backend = load_backend(
            strategy=strategy,
            name="google-oauth2",
            redirect_uri="https://profile.intra.42.fr/users/aanjaimi",
        )

        authorization_url = backend.auth_url()
        return Response({"authorization_url": authorization_url})


class GoogleCallbackAPI(APIView):
    def get(self, request):
        code = request.GET.get("code", None)
        if code is None:
            return Response(
                {"error": "Code not found"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            strategy = load_strategy(request)
            backend = load_backend(
                strategy=strategy,
                name="google-oauth2",
                redirect_uri="https://profile.intra.42.fr/users/aanjaimi",
            )

            # Complete the authentication process
            user = backend.complete(request=request)

            # Create JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Return tokens and user data
            return Response(
                {
                    "access_token": access_token,
                    "refresh_token": str(refresh),
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "name": user.get_full_name(),
                    },
                }
            )

        except (MissingBackend, AuthException) as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
