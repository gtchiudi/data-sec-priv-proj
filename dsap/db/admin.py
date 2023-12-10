from django.contrib import admin
from .models import *


class requestListView(admin.ModelAdmin):
    list_display = ('firstName', 'lastName', 'encrypted_gender',
                    'height', 'weight', 'encrypted_age', 'healthHistory')


admin.site.register(health, requestListView)
admin.site.register(User)
