from django.dispatch import receiver
from django.contrib.auth.hashers import make_password
from django.db.models.signals import pre_save
from django.db import models
import uuid
import random
import faker
add = False


class health(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    firstName = models.CharField(max_length=64)
    lastName = models.CharField(max_length=64)
    gender = models.BooleanField(default=True)  # true = male; false = female
    age = models.IntegerField(default=0)
    weight = models.FloatField(default=0)
    height = models.FloatField(default=0)
    healthHistory = models.CharField(max_length=512, null=True, blank=True)


class User(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = models.CharField(max_length=64)
    # Increased max_length to accommodate hashed password
    password = models.CharField(max_length=128)
    group = models.CharField(max_length=64)


@receiver(pre_save, sender=User)
def hash_user_password(sender, instance, **kwargs):
    # Check if the password is set and unhashed
    # Check if already hashed
    if instance.password and not instance.password.startswith('pbkdf2_'):
        instance.password = make_password(instance.password)

# fake = faker.Faker()

# data = [
#     {
#         'firstName': fake.first_name(),
#         'lastName': fake.last_name(),
#         'gender': random.choice([True, False]),
#         'age': random.randint(18, 100),
#         'weight': round(random.uniform(50, 100), 2),
#         'height': round(random.uniform(150, 190), 2),
#         'healthHistory': fake.text(max_nb_chars=512),
#     }
#     for _ in range(100)
# ]

# instances = [health(**item) for item in data]

# if add:
#     health.objects.bulk_create(instances)
