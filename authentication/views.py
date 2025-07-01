from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import (
    RegisterSerializer, LoginSerializer, UserSerializer,
    VerifyEmailSerializer, RequestPasswordResetSerializer, ResetPasswordSerializer
)
from django.contrib.auth.models import User
from .models import EmailVerificationToken, PasswordResetToken
from .utils import send_verification_email, send_password_reset_email
import uuid
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.shortcuts import render, redirect
from django.http import HttpResponse

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_summary="Register a new user",
        operation_description="""
        Creates a new user account in the system.

        ### Password Requirements
        - Must be at least 8 characters long
        - Should not be too common or easily guessable
        
        ### Required Fields
        - username: A unique username for the account
        - email: A valid email address (must be unique)
        - password: User's secure password
        
        ### After Registration
        After successful registration, a verification email will be sent to the provided
        email address. The user must verify their email before they can log in.
        
        ### Example Request
        ```json
        {
            "username": "johndoe",
            "email": "john.doe@example.com",
            "password": "securePassword123"
        }
        ```
        """,
        request_body=RegisterSerializer,
        responses={
            201: openapi.Response(
                description="User successfully registered",
                schema=UserSerializer,
                examples={
                    "application/json": {
                        "message": "User registered successfully. Please check your email to verify your account.",
                        "user": {
                            "id": 1,
                            "username": "johndoe",
                            "email": "john.doe@example.com",
                            "first_name": "",
                            "last_name": ""
                        }
                    }
                }
            ),
            400: openapi.Response(
                description="Bad request - validation errors",
                examples={
                    "application/json": {
                        "username": ["A user with that username already exists."],
                        "email": ["A user with that email already exists."],
                        "password": ["Password must be at least 8 characters long."]
                    }
                }
            )
        },
        tags=['User Management']
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # Send verification email
            send_verification_email(user)
            # Mark user as inactive until email is verified
            user.is_active = False
            user.save()

            return Response({
                "message": "User registered successfully. Please check your email to verify your account.",
                "user": UserSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_summary="Login to get auth tokens",
        operation_description="""
        Authenticates a user and returns JWT access and refresh tokens.
        
        ### Required Fields
        - email: Your registered email address
        - password: Your account password
        
        ### Response Details
        The response includes:
        - username: The username of the authenticated user
        - access: JWT access token (valid for 1 hour)
        - refresh: JWT refresh token (valid for 2 days)
        - access_expires: Access token expiration timestamp
        - refresh_expires: Refresh token expiration timestamp
        
        ### Using the Token
        Use the access token in subsequent requests by including it in the
        Authorization header as: `Bearer {access_token}`
        
        ### Example Request
        ```json
        {
            "email": "john.doe@example.com",
            "password": "yourSecurePassword"
        }
        ```
        """,
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'password'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='User email address'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, format='password', description='User password'),
            }
        ),
        responses={
            200: openapi.Response(
                description="Login successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'username': openapi.Schema(type=openapi.TYPE_STRING, description='Username of authenticated user'),
                        'access': openapi.Schema(type=openapi.TYPE_STRING, description='JWT access token'),
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='JWT refresh token'),
                        'access_expires': openapi.Schema(type=openapi.TYPE_INTEGER, description='Access token expiration timestamp'),
                        'refresh_expires': openapi.Schema(type=openapi.TYPE_INTEGER, description='Refresh token expiration timestamp'),
                    }
                ),
                examples={
                    "application/json": {
                        "username": "johndoe",
                        "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                        "access_expires": 1719972457,
                        "refresh_expires": 1720058857
                    }
                }
            ),
            400: openapi.Response(
                description="Invalid credentials",
                examples={
                    "application/json": {
                        "non_field_errors": ["Invalid credentials"]
                    }
                }
            ),
            401: openapi.Response(
                description="Email not verified",
                examples={
                    "application/json": {
                        "error": "Email not verified. Please check your inbox for the verification link."
                    }
                }
            )
        },
        tags=['Authentication']
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            # Additional check for email verification
            email = request.data.get('email', '')
            try:
                user = User.objects.get(email=email)
                if not user.is_active:
                    return Response(
                        {"error": "Email not verified. Please check your inbox for the verification link."},
                        status=status.HTTP_401_UNAUTHORIZED
                    )
            except User.DoesNotExist:
                # Let the serializer handle this case
                pass

            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def handle_exception(self, exc):
        """Custom exception handler for authentication issues"""
        if isinstance(exc, permissions.exceptions.NotAuthenticated):
            return Response(
                {"error": "Authentication failed", "detail": "Token may be expired or invalid"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        return super().handle_exception(exc)

    @swagger_auto_schema(
        operation_summary="Get authenticated user's profile",
        operation_description="""
        Retrieves the profile information of the currently authenticated user.
        
        ### Authentication Required
        This endpoint requires authentication with a valid JWT token.
        Include the token in your request headers as:
        `Authorization: Bearer {access_token}`
        
        ### Response Data
        Returns user profile information including:
        - User ID
        - Username
        - Email address
        - First name (if provided)
        - Last name (if provided)
        
        ### Example Response
        ```json
        {
            "id": 1,
            "username": "johndoe",
            "email": "john.doe@example.com",
            "first_name": "John",
            "last_name": "Doe"
        }
        ```
        """,
        responses={
            200: UserSerializer,
            401: openapi.Response(
                description="Authentication failed",
                examples={
                    "application/json": {
                        "error": "Authentication failed",
                        "detail": "Token may be expired or invalid"
                    }
                }
            )
        },
        tags=['User Profile']
    )
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

class VerifyEmailView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_summary="Verify user email",
        operation_description="""
        Verifies a user's email address using the token sent to their email.
        
        ### Required Field
        - token: The verification token received in the email
        
        ### Example Request
        ```json
        {
            "token": "a1b2c3d4e5f6g7h8i9j0..."
        }
        ```
        
        ### Notes
        - Tokens are valid for 24 hours from creation
        - Each token can only be used once
        - After verification, the user account will be activated
        """,
        request_body=VerifyEmailSerializer,
        responses={
            200: openapi.Response(
                description="Email successfully verified",
                examples={
                    "application/json": {
                        "message": "Email verified successfully. You can now log in."
                    }
                }
            ),
            400: openapi.Response(
                description="Invalid or expired token",
                examples={
                    "application/json": {
                        "error": "Invalid or expired token."
                    }
                }
            ),
            404: openapi.Response(
                description="Token not found",
                examples={
                    "application/json": {
                        "error": "Token not found."
                    }
                }
            )
        },
        tags=['Email Verification']
    )
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        if serializer.is_valid():
            token_value = serializer.validated_data['token']

            try:
                token = EmailVerificationToken.objects.get(token=token_value)

                if not token.is_valid():
                    return Response(
                        {"error": "Invalid or expired token."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Verify the user
                user = token.user
                user.is_active = True
                user.save()

                # Mark token as used
                token.verified = True
                token.save()

                return Response(
                    {"message": "Email verified successfully. You can now log in."},
                    status=status.HTTP_200_OK
                )

            except EmailVerificationToken.DoesNotExist:
                return Response(
                    {"error": "Token not found."},
                    status=status.HTTP_404_NOT_FOUND
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RequestPasswordResetView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_summary="Request password reset email",
        operation_description="""
        Initiates the password reset process by sending a reset link to the user's email.
        
        ### Required Field
        - email: The email address associated with the user account
        
        ### Security Note
        For security reasons, this endpoint always returns a success message,
        even if the email does not exist in the system.
        
        ### Example Request
        ```json
        {
            "email": "john.doe@example.com"
        }
        ```
        """,
        request_body=RequestPasswordResetSerializer,
        responses={
            200: openapi.Response(
                description="Password reset email sent (if email exists)",
                examples={
                    "application/json": {
                        "message": "If your email is registered, you will receive a password reset link."
                    }
                }
            ),
            400: openapi.Response(
                description="Invalid email format",
                examples={
                    "application/json": {
                        "email": ["Enter a valid email address."]
                    }
                }
            )
        },
        tags=['Password Reset']
    )
    def post(self, request):
        serializer = RequestPasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            # Try to find the user
            try:
                user = User.objects.get(email=email)
                send_password_reset_email(user)
            except User.DoesNotExist:
                # For security, we don't reveal if the email exists or not
                pass

            # Always return success for security
            return Response(
                {"message": "If your email is registered, you will receive a password reset link."},
                status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(
        operation_summary="Reset user password",
        operation_description="""
        Resets the user's password using a valid reset token.
        
        ### Required Fields
        - token: The password reset token received in the email
        - password: The new password
        - confirm_password: Confirmation of the new password (must match password)
        
        ### Password Requirements
        - Must be at least 8 characters long
        - Should not be too common or easily guessable
        - Should not be similar to your other personal information
        
        ### Example Request
        ```json
        {
            "token": "a1b2c3d4e5f6g7h8i9j0...",
            "password": "newSecurePassword123",
            "confirm_password": "newSecurePassword123"
        }
        ```
        
        ### Notes
        - Password reset tokens are valid for 1 hour from creation
        - Each token can only be used once
        """,
        request_body=ResetPasswordSerializer,
        responses={
            200: openapi.Response(
                description="Password reset successful",
                examples={
                    "application/json": {
                        "message": "Password has been reset successfully."
                    }
                }
            ),
            400: openapi.Response(
                description="Invalid data or expired token",
                examples={
                    "application/json": {
                        "error": "Invalid or expired token.",
                        "password": ["This password is too common."],
                        "confirm_password": ["Passwords do not match."]
                    }
                }
            ),
            404: openapi.Response(
                description="Token not found",
                examples={
                    "application/json": {
                        "error": "Token not found."
                    }
                }
            )
        },
        tags=['Password Reset']
    )
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            token_value = serializer.validated_data['token']
            password = serializer.validated_data['password']

            try:
                token = PasswordResetToken.objects.get(token=token_value)

                if not token.is_valid():
                    return Response(
                        {"error": "Invalid or expired token."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Reset password
                user = token.user
                user.set_password(password)
                user.save()

                # Mark token as used
                token.used = True
                token.save()

                return Response(
                    {"message": "Password has been reset successfully."},
                    status=status.HTTP_200_OK
                )

            except PasswordResetToken.DoesNotExist:
                return Response(
                    {"error": "Token not found."},
                    status=status.HTTP_404_NOT_FOUND
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailLinkView(APIView):
    """
    View to handle email verification when user clicks the link in the email.
    This receives a GET request with the token in the URL.
    """
    permission_classes = []  # No permissions required for email links

    @swagger_auto_schema(
        operation_summary="Verify user email via link",
        operation_description="""
        Verifies a user's email address when they click the link sent to their email.
        This endpoint handles GET requests from email links and serves an HTML response.
        
        ### How It Works
        1. User receives an email with a verification link
        2. User clicks the link which sends a GET request to this endpoint
        3. The system verifies the token and activates the user's account
        4. User sees a success message and can now log in
        
        ### Notes
        - Tokens are valid for 24 hours from creation
        - Each token can only be used once
        - This endpoint returns HTML content, not JSON
        """,
        manual_parameters=[
            openapi.Parameter(
                'token',
                openapi.IN_PATH,
                description="Email verification token from the email link",
                type=openapi.TYPE_STRING,
                required=True
            ),
        ],
        responses={
            200: openapi.Response(description="Email successfully verified (returns HTML)"),
            400: openapi.Response(description="Invalid or expired token (returns HTML)"),
            404: openapi.Response(description="Token not found (returns HTML)")
        },
        tags=['Email Verification']
    )
    def get(self, request, token):
        try:
            verification_token = EmailVerificationToken.objects.get(token=token)

            if not verification_token.is_valid():
                return HttpResponse(
                    "<h1>Invalid Verification Link</h1>"
                    "<p>The link has expired or has already been used.</p>"
                    "<p>Please request a new verification email.</p>",
                    status=400
                )

            # Verify user and activate account
            user = verification_token.user
            user.is_active = True
            user.save()

            # Mark token as used
            verification_token.verified = True
            verification_token.save()

            return HttpResponse(
                "<h1>Email Verified Successfully</h1>"
                "<p>Your email has been verified. You can now log in.</p>",
                status=200
            )

        except EmailVerificationToken.DoesNotExist:
            return HttpResponse(
                "<h1>Invalid Verification Link</h1>"
                "<p>The verification link is invalid.</p>"
                "<p>Please request a new verification email.</p>",
                status=404
            )

class ResetPasswordLinkView(APIView):
    """
    View to handle password reset when user clicks the link in the email.
    Serves a password reset form and handles form submission.
    """
    permission_classes = []  # No permissions required for email links

    def get_reset_form_html(self, token, errors=None):
        """Helper to generate password reset form HTML"""
        errors_html = ""
        if errors:
            errors_html = "<div class='errors'>"
            for field, field_errors in errors.items():
                for error in field_errors:
                    errors_html += f"<p class='error'>{field}: {error}</p>"
            errors_html += "</div>"

        return f"""
             <html>
                    <head>
                        <title>Reset Password</title>
                        <style>
                            body {{ font-family: Arial, sans-serif; padding: 20px; max-width: 500px; margin: 0 auto; }}
                            h1 {{ color: #333; }}
                            .form-group {{ margin-bottom: 15px; }}
                            label {{ display: block; margin-bottom: 5px; }}
                            input[type="password"] {{ width: 100%; padding: 8px; box-sizing: border-box; }}
                            button {{ background: #4CAF50; color: white; border: none; padding: 10px 15px; cursor: pointer; }}
                            .error {{ color: red; margin-top: 5px; }}
                            .errors {{ background: #ffebee; padding: 15px; margin-bottom: 20px; border-radius: 4px; }}
                        </style>
                    </head>
                    <body>
                        <h1>Reset Your Password</h1>
                        {errors_html}
                        <form method="POST">
                            <input type="hidden" name="token" value="{token}">
                            <div class="form-group">
                                <label for="password">New Password</label>
                                <input type="password" id="password" name="password" required>
                            </div>
                            <div class="form-group">
                                <label for="confirm_password">Confirm Password</label>
                                <input type="password" id="confirm_password" name="confirm_password" required>
                            </div>
                            <button type="submit">Reset Password</button>
                        </form>
                    </body>
             </html>
            """


    def get(self, request, token):
        try:
            reset_token = PasswordResetToken.objects.get(token=token)

            if not reset_token.is_valid():
                return HttpResponse(
                    "<h1>Expired Link</h1>"
                    "<p>This password reset link has expired.</p>"
                    "<p>Please request a new password reset.</p>",
                    status=400
                )

            return HttpResponse(self.get_reset_form_html(token))

        except PasswordResetToken.DoesNotExist:
            return HttpResponse(
                "<h1>Invalid Link</h1>"
                "<p>This password reset link is invalid.</p>"
                "<p>Please check the link or request a new one.</p>",
                status=404
            )

    def post(self, request, token):
        try:
            reset_token = PasswordResetToken.objects.get(token=token)

            if not reset_token.is_valid():
                return HttpResponse(
                    "<h1>Expired Link</h1>"
                    "<p>This password reset link has expired.</p>"
                    "<p>Please request a new password reset.</p>",
                    status=400
                )

            # Prepare data for validation
            data = {
                'token': token,
                'password': request.POST.get('password'),
                'confirm_password': request.POST.get('confirm_password')
            }

            serializer = ResetPasswordSerializer(data=data)

            if serializer.is_valid():
                # Update password
                user = reset_token.user
                user.set_password(serializer.validated_data['password'])
                user.save()

                # Invalidate token
                reset_token.used = True
                reset_token.save()

                return HttpResponse(
                    "<h1>Password Reset Successful</h1>"
                    "<p>Your password has been updated successfully.</p>"
                    "<p>You can now log in with your new password.</p>"
                )

            # Show form with validation errors
            return HttpResponse(
                self.get_reset_form_html(token, serializer.errors),
                status=400
            )

        except PasswordResetToken.DoesNotExist:
            return HttpResponse(
                "<h1>Invalid Link</h1>"
                "<p>This password reset link is invalid.</p>"
                "<p>Please check the link or request a new one.</p>",
                status=404
            )
