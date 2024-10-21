from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

User = get_user_model()


class GoogleOAuthBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # For Google OAuth, we'll use the email as the username
        try:
            user = User.objects.get(email=username)
            return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
