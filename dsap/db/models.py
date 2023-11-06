from django.db import models
import uuid


class health(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    firstName = models.CharField(max_length=64)
    lastName = models.CharField(max_length=64)
    gender = models.BooleanField(default=True)  # true = male; false = female
    age = models.IntegerField(default=0)
    weight = models.FloatField(default=0)
    height = models.FloatField(default=0)
    healthHistory = models.CharField(max_length=512, null=True, blank=True)
