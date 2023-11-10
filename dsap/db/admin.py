from django.contrib import admin
from .models import *


class requestListView(admin.ModelAdmin):
    list_display = ('firstName', 'lastName', 'gender',
                    'height', 'weight', 'age', 'healthHistory')


admin.site.register(health, requestListView)
