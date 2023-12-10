from django.dispatch import receiver
from django.contrib.auth.hashers import make_password
from django.db.models.signals import pre_save, post_save
from django.db import models
from django.contrib.auth.models import AbstractUser
from cryptography.fernet import Fernet
from django.conf import settings
from django_cryptography.fields import encrypt
import uuid
import random
import faker
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rest_framework.authtoken.models import Token

# FERNET_KEY = settings.FERNET_KEY
# cipher_suite = Fernet(FERNET_KEY)

add = False

# Function to encrypt data


# def encrypt(data):
#     bytes_data = str(data).encode()
#     encrypted_data = cipher_suite.encrypt(bytes_data)
#     return encrypted_data.decode()

# # Function to decrypt data


# def decrypt(encrypted_data):
#     decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
#     return decrypted_data.decode()


class health(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    firstName = models.CharField(max_length=64)
    lastName = models.CharField(max_length=64)
    # encrypted_gender = models.BinaryField(null=True, blank=True)
    # encrypted_age = models.BinaryField(null=True, blank=True)
    encrypted_gender = encrypt(models.BooleanField(default=False))
    encrypted_age = encrypt(models.IntegerField(default=0))
    weight = models.FloatField(default=0)
    height = models.FloatField(default=0)
    healthHistory = models.CharField(max_length=512, null=True, blank=True)

    # def save(self, *args, **kwargs):
    #     # encrypt age and gender
    #     if self.gender:
    #         self.encrypted_gender = encrypt(self.gender)
    #     if self.age:
    #         self.encrypted_age = encrypt(self.age)
    #     super(health, self).save(*args, **kwargs)


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


# fake = faker.Faker()

# data = [
#     {
#         'firstName': fake.first_name(),
#         'lastName': fake.last_name(),
#         'encrypted_gender': random.choice([True, False]),
#         'encrypted_age': random.randint(18, 100),
#         'weight': round(random.uniform(50, 100), 2),
#         'height': round(random.uniform(150, 190), 2),
#         'healthHistory': fake.text(max_nb_chars=512),
#     }
#     for _ in range(100)
# ]

# instances = [health(**item) for item in data]

# if add:
#     health.objects.bulk_create(instances)
#     add = False
