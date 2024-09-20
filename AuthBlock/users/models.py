from django.db import models
from django.contrib.auth.models import User


class Profile(models.Model):
    USER_TYPE_CHOICES = [
        ('student', 'Student'),
        ('issuer', 'Issuer'),
        ('verifier', 'Verifier'),
    ]

    GENDER_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='profile')
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES)
    national_id = models.CharField(max_length=20, unique=True)
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(
        max_length=1, choices=GENDER_CHOICES, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} - {self.user_type}"

    class Meta:
        permissions = [
            ('view_own_documents', 'Can view own documents'),
            ('upload_document', 'Can upload document'),
        ]



