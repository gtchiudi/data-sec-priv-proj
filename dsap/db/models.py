import os
import uuid
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.db.models.signals import pre_save, post_save
from django.db import models
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from .utils import encrypt


class Health(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    firstName = models.CharField(max_length=64)
    lastName = models.CharField(max_length=64)
    encrypted_gender = models.CharField(max_length=64, null=True, blank=True)
    encrypted_age = models.CharField(max_length=64, null=True, blank=True)
    weight = models.FloatField(default=0)
    height = models.FloatField(default=0)
    healthHistory = models.CharField(max_length=512, null=True, blank=True)

    @receiver(pre_save, sender='db.Health')
    def encryptAgeGender(sender, instance, **kwargs):
        instance.encrypted_gender = encrypt(
            instance.encrypted_gender == True)
        instance.encrypted_age = encrypt(int(instance.encrypted_age))


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=64, unique=True)
    # Increased max_length to accommodate hashed password
    salt = models.CharField(max_length=128)
    password = models.CharField(max_length=128)
    group = models.CharField(max_length=64)
    pass


@receiver(pre_save, sender=User)
def hash_user_password(sender, instance, **kwargs):
    # Check if the password is set and unhashed
    if instance.password and not instance.salt:  # Ensure password exists and salt is not set
        salt = os.urandom(16)
        instance.salt = salt.hex()  # Store salt as hexadecimal string in the database

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=150000,
            salt=salt,
            length=32,
        )
        password_bytes = instance.password.encode(
            'utf-8')  # Convert password to bytes
        hashed_password = kdf.derive(password_bytes).hex()
        instance.password = hashed_password  # Store hashed password in the database


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
