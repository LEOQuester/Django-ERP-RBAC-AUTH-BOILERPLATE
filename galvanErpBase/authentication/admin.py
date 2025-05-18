from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import gettext_lazy as _
from .models import User

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'phone_number', 'nic', 'is_staff', 'is_active', 'is_deleted')
    search_fields = ('email', 'first_name', 'last_name', 'phone_number', 'nic')
    ordering = ('email',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('username', 'first_name', 'last_name', 'phone_number', 'nic', 'gender','address', 'dob', 'profile_pic')}),
        (_('Verification'), {'fields': ('is_email_verified', 'is_phone_verified', 'is_verified')}),
        (_('Status'), {
            'fields': ('is_active', 'is_deleted'),
        }),
        (_('Permissions'), {
            'fields': ('is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_('Important dates'), {'fields': ('last_login',)}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'phone_number', 'password1', 'password2'),
        }),
    )
    
    readonly_fields = ('is_verified',)
    
    def get_queryset(self, request):
        # Show all users in admin, including deleted ones
        return super().get_queryset(request)
