# import random
# from django.shortcuts import render, redirect
# from django.contrib.auth import authenticate, login
# from django.core.mail import send_mail
# from django.http import HttpResponseForbidden
# from django.views import View
# from django.utils.decorators import method_decorator
# from django.contrib.auth.decorators import login_required
# from rest_framework import generics
# from rest_framework.permissions import AllowAny
# from django.contrib.auth import get_user_model
# from django.contrib.auth import get_user_model
# from django.contrib.auth.tokens import default_token_generator
# from django.utils.http import urlsafe_base64_encode
# from rest_framework import generics, permissions
# from rest_framework.response import Response
# from rest_framework import status
# from django.urls import reverse
# from django.core.mail import send_mail
# from .serializers import SetAccountSerializer, ProfileSerializer
# from django.utils.http import urlsafe_base64_decode
# from django.utils.encoding import force_str
# from django.contrib.auth import get_user_model
# from django.contrib.auth.tokens import default_token_generator
# from rest_framework import generics, permissions
# from rest_framework.response import Response
# from rest_framework import status

# User = get_user_model()

# class EmailRegistrationAPIView(generics.CreateAPIView):
#     permission_classes = [permissions.AllowAny]

#     def create(self, request, *args, **kwargs):
#         email = request.data.get('email')
#         user_type = request.data.get('user_type')

#         if email and user_type:
#             if User.objects.filter(email=email).exists():
#                 return Response({'error': 'Email already registered'}, status=status.HTTP_400_BAD_REQUEST)

#             user = User.objects.create_user(username=email, email=email)
#             user.save()

#             self.send_registration_email(user)

#             return Response({'success': 'Registration email sent successfully'}, status=status.HTTP_201_CREATED)

#         return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)

#     def send_registration_email(self, user):
#         token = default_token_generator.make_token(user)
#         uid = urlsafe_base64_encode(user.pk.encode())  # Ensure UID is encoded properly

#         setup_url = self.request.build_absolute_uri(
#             reverse('set_accounts', kwargs={'uidb64': uid, 'token': token})
#         )

#         subject = 'Complete Your Registration'
#         message = f"Click the link below to set your password and complete your registration:\n{setup_url}"
#         from_email = 'your_email@example.com'  # Replace with actual email
#         recipient_list = [user.email]

#         send_mail(subject, message, from_email, recipient_list)

# class SetAccountView(generics.GenericAPIView):
#     permission_classes = [permissions.AllowAny]
#     serializer_class = SetAccountSerializer

#     def post(self, request, uidb64, token):
#         try:
#             uid = force_str(urlsafe_base64_decode(uidb64))
#             user = User.objects.get(pk=uid)
#         except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#             user = None
        
#         # Check if the token is valid
#         if user is not None and default_token_generator.check_token(user, token):
#             user_data = request.data
            
#             # Update user information
#             user.username = user_data.get('username')
#             user.set_password(user_data.get('new_password1'))  # Set the new password
#             user.first_name = user_data.get('first_name')
#             user.last_name = user_data.get('last_name')
#             user.save()  # Save the user information
            
#             # Create or update the profile
#             profile_data = {
#                 'user': user,  # Directly assign the user instance
#                 'date_of_birth': user_data.get('date_of_birth'),
#                 'national_id': user_data.get('national_id'),
#                 'gender': user_data.get('gender'),
#                 'user_type': user_data.get('user_type'),
#             }
#             profile_serializer = ProfileSerializer(data=profile_data)
#             profile_serializer.is_valid(raise_exception=True)
#             profile_serializer.save()  # Save the profile if valid
            
#             return Response({"success": "Account and profile created successfully"}, status=status.HTTP_201_CREATED)

#         return Response({"error": "Invalid token or user ID"}, status=status.HTTP_400_BAD_REQUEST)
    
# # User = get_user_model()

# # class SetAccountView(generics.GenericAPIView):
# #     permission_classes = [permissions.AllowAny]
# #     serializer_class = SetAccountSerializer

# #     def post(self, request, uidb64, token):
# #         try:
# #             uid = force_str(urlsafe_base64_decode(uidb64))
# #             user = User.objects.get(pk=uid)
# #         except (TypeError, ValueError, OverflowError, User.DoesNotExist):
# #             user = None
        
# #         # Check if the token is valid
# #         if user is not None and default_token_generator.check_token(user, token):
# #             user_data = request.data
            
# #             # Update the user with the provided data
# #             user.username = user_data.get('username')
# #             user.set_password(user_data.get('new_password1'))  # Set the new password
# #             user.first_name = user_data.get('first_name')
# #             user.last_name = user_data.get('last_name')
# #             user.save()

# #             # Create the profile
# #             profile_data = {
# #                 'user': user.id,
# #                 'date_of_birth': user_data.get('date_of_birth'),
# #                 'national_id': user_data.get('national_id'),
# #                 'gender': user_data.get('gender'),
# #                 'user_type': user_data.get('user_type'),
# #             }
# #             profile_serializer = ProfileSerializer(data=profile_data)
# #             profile_serializer.is_valid(raise_exception=True)
# #             profile_serializer.save()
            
# #             return Response({"success": "Account and profile created successfully"}, status=status.HTTP_201_CREATED)

# #         return Response({"error": "Invalid token or user ID"}, status=status.HTTP_400_BAD_REQUEST)
    
# class LoginView(generics.GenericAPIView):
#     permission_classes = [AllowAny]

#     def post(self, request):
#         username_or_email = request.POST.get('username')
#         password = request.POST.get('password')

#         # Authenticate user by either username or email
#         user = authenticate(request, username=username_or_email, password=password)

#         if user is not None:
#             # Generate a 6-digit OTP
#             otp = random.randint(100000, 999999)

#             # Send OTP to user's email
#             send_mail(
#                 'Your OTP Code',
#                 f'Your OTP code is {otp}.',
#                 'from@example.com',  # Replace with your email address
#                 [user.email],
#                 fail_silently=False,
#             )

#             # Store OTP and user ID in session
#             request.session['otp'] = otp
#             request.session['user_id'] = user.id

#             # Redirect to the OTP verification page
#             return redirect('otp_verification_page')  # Ensure this URL exists

#         # If authentication fails, reload login page with an error message
#         form = AuthenticationForm(request, data=request.POST)
#         return render(request, 'users/login.html', {'form': form, 'error': 'Invalid credentials'})

# class OTPVerificationView(generics.GenericAPIView):
#     def post(self, request):
#         input_otp = request.POST.get('otp')
#         stored_otp = request.session.get('otp')
#         user_id = request.session.get('user_id')

#         # Ensure OTP and user ID are available in the session
#         if not input_otp or not stored_otp or not user_id:
#             return render(request, 'users/otp_verification.html', {'error': 'Session expired or invalid data'})

#         # Validate the OTP
#         if input_otp == str(stored_otp):
#             try:
#                 # Fetch the user based on session user ID
#                 user = User.objects.get(id=user_id)
#             except User.DoesNotExist:
#                 return render(request, 'users/otp_verification.html', {'error': 'Invalid user'})

#             # Log the user in after successful OTP validation
#             login(request, user, backend='django.contrib.auth.backends.ModelBackend')

#             # Redirect based on user type, assuming user_type is stored in a Profile model
#             user_type = getattr(user.profile, 'user_type', None)

#             if user_type == 'student':
#                 return redirect('students_page')  # Redirect to student's page
#             elif user_type == 'issuer':
#                 return redirect('issuers_page')  # Redirect to issuer's page
#             elif user_type == 'verifier':
#                 return redirect('verifiers_page')  # Redirect to verifier's page

#             # Default redirect if user type is not recognized
#             return redirect('default_page')

#         # If OTP is invalid, return to the OTP verification page with an error
#         return render(request, 'users/otp_verification.html', {'error': 'Invalid OTP'})

# # Views for Students, Issuers, and Verifiers, restricted based on user type

import random
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.shortcuts import redirect, render
from rest_framework.permissions import AllowAny
from rest_framework import generics
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.urls import reverse
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.views import View
from django.shortcuts import render
from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from .models import Profile
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.models import User
from rest_framework import generics
from django.contrib.auth import login
from .serializers import *
from django.contrib.auth.forms import AuthenticationForm


User = get_user_model()

from django.shortcuts import render,redirect

def index(request):
    return render(request, 'users/index.html')

class EmailRegistrationView(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = EmailRegistrationSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()  # Save user and profile via the serializer
            self.send_registration_email(user)
            # Redirect to 'new_registration.html' upon success
            return render(request, 'users/new_registration.html', {'email': user.email})

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_registration_email(self, user):
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(str(user.pk).encode())
        user_type = user.profile.user_type
        setup_url = self.request.build_absolute_uri(
            reverse('set_account', kwargs={'uidb64': uid, 'token': token, 'user_type': user_type})  # Ensure correct URL name and include user_type
         )


        subject = 'Complete Your Registration'
        message = f"Click the link below to set your password and complete your registration:\n{setup_url}"
        from_email = 'your_email@example.com'  # Replace with actual email
        recipient_list = [user.email]

        send_mail(subject, message, from_email, recipient_list)

class SetAccountView(generics.GenericAPIView):
    serializer_class = SetAccountSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request, uidb64, token, user_type):
        return render(request, 'users/AccountSetup.html', {
        'uidb64': uidb64,
        'token': token, 
        'user_type': user_type,  
        })


    def post(self, request, uidb64, token,user_type):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                serializer = self.get_serializer(data=request.data)
                if serializer.is_valid():
                    serializer.save(user)

                    # Check user_type and redirect accordingly
                    user_type = user.profile.user_type
                    if user_type == 'student':
                        return redirect(reverse('students_page'))
                    elif user_type == 'issuer':
                        return redirect(reverse('issuers_page'))
                    elif user_type == 'verifier':
                        return redirect(reverse('verifiers_page'))
                    else:
                        return Response({'error': 'Invalid user type'}, status=status.HTTP_400_BAD_REQUEST)

                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': 'Invalid token or UID'}, status=status.HTTP_400_BAD_REQUEST)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
            print(f"Exception: {e}")
            return Response({'error': 'Invalid UID'}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        # Render the login form
        form = AuthenticationForm()
        return render(request, 'users/login.html', {'form': form})

    def post(self, request, *args, **kwargs):
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username_or_email = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')

            # Authenticate the user using the username or email
            user = authenticate(request, username=username_or_email, password=password)

            if user is not None:
                # Generate a 6-digit OTP
                otp = random.randint(100000, 999999)

                # Send OTP to user's email
                send_mail(
                    'Your OTP Code',
                    f'Your OTP code is {otp}.',
                    'from@example.com',  # Replace with your email address
                    [user.email],
                    fail_silently=False,
                )

                # Store OTP and user ID in session
                request.session['otp'] = otp
                request.session['user_id'] = user.id

                # Redirect to OTP verification page
                return redirect('otp_verification')  # Ensure this URL exists

            else:
                # If authentication fails, reload login page with an error message
                return render(request, 'users/login.html', {'form': form, 'error': 'Invalid credentials'})
        else:
            # If form validation fails (e.g. missing fields), show form with errors
            return render(request, 'users/login.html', {'form': form})
        
class OTPVerificationView(View):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        # Render the OTP verification template on GET request
        return render(request, 'users/otp_verification.html', {})

    def post(self, request, *args, **kwargs):
        # Validate the OTP input with the serializer
        serializer = OTPVerificationSerializer(data=request.POST)

        if serializer.is_valid():
            input_otp = serializer.validated_data['otp']
            stored_otp = request.session.get('otp')
            user_id = request.session.get('user_id')

            # Ensure OTP and user ID are available in the session
            if not stored_otp or not user_id:
                return render(request, 'users/otp_verification.html', {'error': 'Session expired or invalid data'})

            # Validate the OTP
            if input_otp == str(stored_otp):
                try:
                    # Fetch the user based on session user ID
                    user = User.objects.get(id=user_id)
                except User.DoesNotExist:
                    return render(request, 'users/otp_verification.html', {'error': 'Invalid user'})

                # Log the user in after successful OTP validation
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')

                # Redirect based on user type
                user_type = getattr(user.profile, 'user_type', None)

                if user_type == 'student':
                    return redirect('students_page')  # Redirect to student's page
                elif user_type == 'issuer':
                    return redirect('issuers_page')  # Redirect to issuer's page
                elif user_type == 'verifier':
                    return redirect('verifiers_page')  # Redirect to verifier's page

                # Default redirect if user type is not recognized
                return redirect('default_page')

            # If OTP is invalid, return to the OTP verification page with an error
            return render(request, 'users/otp_verification.html', {'error': 'Invalid OTP'})

        # If serializer is not valid, render the form again with error messages
        return render(request, 'users/otp_verification.html', {'form': serializer, 'error': 'Invalid data'})
    
@method_decorator(login_required, name='dispatch')
class StudentView(View):
    def get(self, request):
        if request.user.profile.user_type != 'student':
            return HttpResponseForbidden("You do not have permission to view this page.")
        return render(request, 'users/students.html')


@method_decorator(login_required, name='dispatch')
class IssuerView(View):
    def get(self, request):
        if request.user.profile.user_type != 'issuer':
            return HttpResponseForbidden("You do not have permission to view this page.")
        return render(request, 'users/issuers.html')


@method_decorator(login_required, name='dispatch')
class VerifierView(View):
    def get(self, request):
        if request.user.profile.user_type != 'verifier':
            return HttpResponseForbidden("You do not have permission to view this page.")
        return render(request, 'users/verifiers.html')