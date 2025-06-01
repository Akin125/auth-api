from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import RegisterSerializer, LoginSerializer, UserSerializer
from django.contrib.auth.models import User
from .models import APIKey
import uuid

class HasAPIKey(permissions.BasePermission):
    """
    Permission class to check if request has a valid API key
    """
    def has_permission(self, request, view):
        return hasattr(request, 'auth') and isinstance(request.auth, APIKey)

class RegisterView(APIView):
    permission_classes = [HasAPIKey]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [HasAPIKey]

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

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
