from django.contrib import admin

from .models import User

#  Register your models here.
#  This will allow you to view the User model in the Django admin panel.
admin.site.register(User)
