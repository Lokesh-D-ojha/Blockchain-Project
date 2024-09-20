# from rest_framework import serializers
# from django.contrib.auth.models import User
# from django.core.exceptions import ValidationError
# from .models import Profile
# from django.contrib.auth.password_validation import validate_password
# from django.contrib.auth import authenticate
# from django.contrib.auth.validators import UnicodeUsernameValidator


# class ProfileSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Profile
#         fields = ['user_type']  # Include only the user_type field here

# class EmailRegistrationSerializer(serializers.ModelSerializer):
#     profile = ProfileSerializer()  # Use ProfileSerializer to handle profile data

#     class Meta:
#         model = User
#         fields = ['email', 'profile']  # Include the profile in fields

#     def validate_email(self, value):
#         # Check if the email already exists
#         if User.objects.filter(email=value).exists():
#             raise serializers.ValidationError("This email is already registered.")
#         return value

#     def create(self, validated_data):
#         # Extract profile data
#         profile_data = validated_data.pop('profile')
#         email = validated_data['email']
        
#         # Create the user and set `is_active` to False
#         user = User.objects.create(email=email, is_active=False)

#         # Create the Profile with the user and user_type from profile data
#         Profile.objects.create(user=user, **profile_data)

#         return user


# from django.contrib.auth import get_user_model
# from rest_framework import serializers
# from .models import Profile

# User = get_user_model()

# class SetAccountSerializer(serializers.Serializer):
#     username = serializers.CharField(max_length=150)
#     new_password1 = serializers.CharField(write_only=True)
#     new_password2 = serializers.CharField(write_only=True)
#     first_name = serializers.CharField(max_length=30)
#     last_name = serializers.CharField(max_length=30)
#     date_of_birth = serializers.DateField(required=False)
#     national_id = serializers.CharField(max_length=20, required=True)
#     gender = serializers.ChoiceField(choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Other')], required=True)
#     user_type = serializers.ChoiceField(choices=[('student', 'Student'), ('issuer', 'Issuer'), ('verifier', 'Verifier')], required=True)

#     def validate(self, attrs):
#         if attrs['new_password1'] != attrs['new_password2']:
#             raise serializers.ValidationError("Passwords do not match.")
#         return attrs
    
# class ProfileSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Profile
#         fields = ['date_of_birth', 'national_id', 'gender', 'user_type']



# class LoginSerializer(serializers.Serializer):
#     username_or_email = serializers.CharField()
#     password = serializers.CharField(write_only=True)

#     def validate(self, attrs):
#         username_or_email = attrs.get('username_or_email')
#         password = attrs.get('password')

#         # Attempt to authenticate the user using either username or email
#         user = None
#         if '@' in username_or_email:
#             # If the input contains '@', assume it's an email
#             user = authenticate(request=self.context.get(
#                 'request'), email=username_or_email, password=password)
#         else:
#             # Otherwise, assume it's a username
#             user = authenticate(request=self.context.get(
#                 'request'), username=username_or_email, password=password)

#         if user is None:
#             raise serializers.ValidationError(
#                 'Invalid username/email or password.')

#         attrs['user'] = user
#         return attrs


from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import Profile
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

User = get_user_model()

class EmailRegistrationSerializer(serializers.ModelSerializer):
    user_type = serializers.ChoiceField(choices=Profile.USER_TYPE_CHOICES, required=True)

    class Meta:
        model = User
        fields = ['email', 'user_type']

    def validate_email(self, value):
        # Check if the email already exists
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered.")
        return value

    def create(self, validated_data):
        # Create the user with email and set `is_active` to False initially
        user = User(email=validated_data['email'], is_active=False)
        user.save()

        # Create the corresponding Profile with `user_type`
        user_type = validated_data['user_type']
        Profile.objects.create(user=user, user_type=user_type)

        return user


class SetAccountSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, required=True)
    new_password1 = serializers.CharField(write_only=True, min_length=8)
    new_password2 = serializers.CharField(write_only=True, min_length=8)
    first_name = serializers.CharField(max_length=150, required=True)
    last_name = serializers.CharField(max_length=150, required=True)
    date_of_birth = serializers.DateField(required=True)
    national_id = serializers.CharField(max_length=20, required=True)
    gender = serializers.ChoiceField(choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Other')])
    user_type = serializers.ChoiceField(choices=Profile.USER_TYPE_CHOICES, required=True)

    def validate(self, attrs):
        if attrs['new_password1'] != attrs['new_password2']:
            raise serializers.ValidationError({"password": "Passwords do not match."})

        # Validate the password using Django's built-in password validators
        validate_password(attrs['new_password1'])

        return attrs

    def save(self, user):
        # Set the new password for the user
        user.set_password(self.validated_data['new_password1'])
        
        # Update user's fields
        user.username = self.validated_data['username']
        user.first_name = self.validated_data['first_name']
        user.last_name = self.validated_data['last_name']
        user.is_active = True
        user.save()

        # Update Profile information for the user
        profile = Profile.objects.get(user=user)
        profile.user_type = self.validated_data['user_type']
        profile.date_of_birth = self.validated_data['date_of_birth']
        profile.national_id = self.validated_data['national_id']
        profile.gender = self.validated_data['gender']
        profile.save()

        return user
    
from django.contrib.auth import authenticate

class LoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        username_or_email = attrs.get('username_or_email')
        password = attrs.get('password')

        # Attempt to authenticate the user using either username or email
        user = None
        request = self.context.get('request')  # Get the request from the serializer context
        if '@' in username_or_email:
            # If the input contains '@', assume it's an email
            user = authenticate(request=request, email=username_or_email, password=password)
        else:
            # Otherwise, assume it's a username
            user = authenticate(request=request, username=username_or_email, password=password)

        if user is None:
            raise serializers.ValidationError('Invalid username/email or password.')

        # Attach the authenticated user to the validated data
        attrs['user'] = user
        return attrs
    
class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)

    def validate_otp(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("OTP must be a 6-digit number.")
        return value