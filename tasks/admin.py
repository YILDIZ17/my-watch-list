from django.contrib import admin

# Register your models here.
from .models import *

admin.site.register(Task)
admin.site.register(FranceConnectProfile)
admin.site.register(GoogleProfile)
admin.site.register(Series)