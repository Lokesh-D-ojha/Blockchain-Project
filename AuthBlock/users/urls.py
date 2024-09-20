# from django.urls import path
# from django.contrib.auth import views as auth_views
# from django.views.generic import TemplateView

# from .views import EmailRegistrationAPIView, SetAccountView, LoginView, index, OTPVerificationView, StudentView, IssuerView, VerifierView

# urlpatterns = [
#     path('', index, name='index'),
#     path('register/', EmailRegistrationAPIView.as_view(),
#          name='email_registration'),
#     path('set_accounts/<uidb64>/<token>/',
#          SetAccountView.as_view(), name='set_accounts'),
#     path('new_registration/', TemplateView.as_view(
#         template_name='users/new_registration.html'), name='new_registration'),
#     path('already_registered/', TemplateView.as_view(
#         template_name='users/already_registered.html'), name='already_registered'),
#     path('login/', LoginView.as_view(), name='login'),
#     path('otp-verification/', OTPVerificationView.as_view(), name='otp_verification_page'),
#     # Add other URL paths for students, issuers, verifiers, and default pages
#     path('students/', StudentView.as_view(), name='students_page'),
#     path('issuers/', IssuerView.as_view(), name='issuers_page'),
#     path('verifiers/', VerifierView.as_view(), name='verifiers_page'),
# # ]

from django.urls import path
from .views import *

urlpatterns = [
    path('', index, name='index'),
    path('register/', EmailRegistrationView.as_view(), name='email_registration'),
    path('set_account/<uidb64>/<token>/<user_type>/', SetAccountView.as_view(), name='set_account'),
    path('students/', StudentView.as_view(), name='students_page'),
    path('issuers/', IssuerView.as_view(), name='issuers_page'),
    path('verifiers/', VerifierView.as_view(), name='verifiers_page'),
    path('login/', LoginView.as_view(), name='login'),
    path('otp-verification/', OTPVerificationView.as_view(), name='otp_verification'),

]
