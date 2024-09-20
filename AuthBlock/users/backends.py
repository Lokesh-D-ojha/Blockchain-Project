from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

User = get_user_model()

class EmailOrUsernameModelBackend(ModelBackend):
    def authenticate(self, request, username=None, email=None, password=None, **kwargs):
        try:
            if email:  # Try to authenticate using email
                user = User.objects.get(email=email)
            else:  # Fallback to username if email is not provided
                user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None

        if user and user.check_password(password):
            return user
        return None
