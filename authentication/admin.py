from django.contrib import admin
from .models import EmailVerificationToken, PasswordResetToken

@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'expires_at', 'verified')
    search_fields = ('user__username', 'user__email')

@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'expires_at', 'used')
    search_fields = ('user__username', 'user__email')
