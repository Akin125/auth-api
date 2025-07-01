# docs/urls.py

"""
URL configuration for API documentation using drf_yasg.

This module sets up Swagger and ReDoc documentation views for the Auth API.
The following documentation endpoints are provided:
- /swagger.json or /swagger.yaml: Raw OpenAPI schema in JSON or YAML format for machine consumption
- /swagger/: Interactive Swagger UI documentation for human exploration and testing
- /redoc/: ReDoc UI documentation for a more user-friendly documentation reading experience
"""

from django.urls import path, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# Create a schema view for the API documentation
schema_view = get_schema_view(
   openapi.Info(
      title="Authentication API",
      default_version='v1',
      description="""
## Authentication API Documentation

This API provides authentication and user management services.

### Features
- User registration with email verification
- JWT token-based authentication
- Password reset functionality
- User profile management

### Authentication
- All endpoints use JWT token authentication 
- Include the token in your request header as: `Authorization: Bearer {token}`
- You can obtain a token through the login endpoint

### Error Handling
- All endpoints return standard HTTP status codes
- Error responses include descriptive messages to help troubleshoot issues

For support, please contact: philipoluseyi@gmail.com
      """,
      terms_of_service="https://www.example.com/terms/",
      contact=openapi.Contact(email="philipoluseyi@gmail.com"),
      license=openapi.License(name="MIT License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

# URL patterns for documentation endpoints
urlpatterns = [
   # Endpoint for raw OpenAPI schema in JSON or YAML format
   # This endpoint provides the raw API schema that can be consumed by automated tools,
   # client generators, or other services that integrate with your API.
   # Usage:
   # - /swagger.json - Returns the API schema in JSON format
   # - /swagger.yaml - Returns the API schema in YAML format
   re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),

   # Swagger UI documentation endpoint
   # This provides an interactive UI that allows users to:
   # - Explore API endpoints
   # - See required parameters and response models
   # - Execute API calls directly from the browser
   # - Test authentication
   # Best for developers who want to integrate with the API
   path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),

   # ReDoc UI documentation endpoint
   # This provides a clean, responsive three-panel documentation view that:
   # - Shows all endpoints in a navigation menu
   # - Displays clear request/response examples
   # - Presents more readable documentation with better organization
   # Best for non-technical users who need to understand the API
   path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
