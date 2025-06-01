from django.contrib import admin
from .models import APIKey

@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ('name', 'service', 'created', 'is_active')
    search_fields = ('name', 'service', 'description')
    readonly_fields = ('key',)
