from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True,
                                    style={'input_type': 'password'})
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("A user with that username already exists.")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)
    access_expires = serializers.CharField(read_only=True)
    refresh_expires = serializers.CharField(read_only=True)

    def validate(self, data):
        email = data.get('email', '')
        password = data.get('password', '')

        # Using a generic error message for security
        error_msg = "Invalid credentials"

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError(error_msg)

        if not user.check_password(password):
            raise serializers.ValidationError(error_msg)

        refresh = RefreshToken.for_user(user)

        # Set custom token lifespans
        from datetime import timedelta

        # Access token valid for 1 hour (default is typically 5 minutes)
        access_token_lifetime = timedelta(hours=1)
        # Refresh token valid for 7 days (default is typically 1 day)
        refresh_token_lifetime = timedelta(days=2)

        refresh.set_exp(lifetime=refresh_token_lifetime)
        refresh.access_token.set_exp(lifetime=access_token_lifetime)

        return {
            'username': user.username,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'access_expires': refresh.access_token.payload['exp'],
            'refresh_expires': refresh.payload['exp'],
        }
