from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import RegisterSerializer, LoginSerializer, UserSerializer
from django.contrib.auth.models import User
from .models import APIKey
import uuid
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

class HasAPIKey(permissions.BasePermission):
    """
    Permission class to check if request has a valid API key
    """
    def has_permission(self, request, view):
        return hasattr(request, 'auth') and isinstance(request.auth, APIKey)

class RegisterView(APIView):
    permission_classes = [HasAPIKey]

    @swagger_auto_schema(
        operation_summary="Register a new user",
        operation_description="""
        Creates a new user account in the system.

        This endpoint requires a valid API key for access. The API key should be
        included in the request headers as 'X-API-Key'.

        Password requirements:
        - Must be at least 8 characters long

        All fields (username, email, password) are required.
        """,
        request_body=RegisterSerializer,
        responses={
            201: openapi.Response(
                description="User successfully registered",
                schema=UserSerializer
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
            ),
            401: "API key missing or invalid"
        },
        tags=['Authentication']
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [HasAPIKey]

    @swagger_auto_schema(
        operation_summary="Login to get auth tokens",
        operation_description="""
        Authenticates a user and returns JWT access and refresh tokens.

        This endpoint requires a valid API key for access. The API key should be
        included in the request headers as 'X-API-Key'.

        The response includes:
        - username: The username of the authenticated user
        - access: JWT access token (valid for 1 hour)
        - refresh: JWT refresh token (valid for 2 days)
        - access_expires: Access token expiration timestamp
        - refresh_expires: Refresh token expiration timestamp

        Use the access token in subsequent requests by including it in the
        Authorization header as: 'Bearer {access_token}'
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
                )
            ),
            400: openapi.Response(
                description="Invalid credentials",
                examples={
                    "application/json": {
                        "non_field_errors": ["Invalid credentials"]
                    }
                }
            ),
            401: "API key missing or invalid"
        },
        tags=['Authentication']
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
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

        This endpoint requires authentication with a valid JWT token.
        The token should be included in the request headers as:
        'Authorization: Bearer {access_token}'

        The access token can be obtained from the login endpoint.
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
