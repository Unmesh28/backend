from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from http import HTTPStatus
from typing import Any

from rest_framework.views import Response, exception_handler
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenRefreshView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/account/', include('accounts.urls', namespace='accounts')),

    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]

# Static Assets
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)


# Schema URLs
urlpatterns += [
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('', SpectacularSwaggerView.as_view(
        url_name='schema'), name='swagger-ui'),
]
