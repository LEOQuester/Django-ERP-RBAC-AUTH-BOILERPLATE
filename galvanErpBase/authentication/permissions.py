from rest_framework import permissions

class IsVerifiedOrAuthenticating(permissions.IsAuthenticated):
    def has_permission(self, request, view):
        # List of views that don't require verification
        auth_views = [
            'register_user',
            'LoginView',
            'CookieTokenRefreshView',
            'TokenVerifyView',
            'LogoutView',
            'verify_otp',
            'send_email_verification',
            'send_phone_verification',
            'ForgotPasswordView',
            'ResetPasswordView'
        ]

        # Always allow access to authentication endpoints
        view_name = view.__class__.__name__
        view_func = getattr(view, view.action) if hasattr(view, 'action') else view
        func_name = view_func.__name__ if hasattr(view_func, '__name__') else ''
        
        if view_name in auth_views or func_name in auth_views:
            return True

        # For all other endpoints, require user to be authenticated AND verified
        is_authenticated = super().has_permission(request, view)
        return is_authenticated and request.user.is_verified