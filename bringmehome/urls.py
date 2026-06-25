"""
URL configuration for bringmehome project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),

# Django built-in auth views (login/logout/password reset, etc.)
    path('accounts/', include('django.contrib.auth.urls')),
    path('accounts/', include('accounts.urls')),



    # 1. We removed 'registry/' so your paths work directly at the root
    # Now /dashboard/, /register/, etc., will all work!
    path('', include('registry.urls')),
]


# Serve media and static files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# """
# URL configuration for bringmehome project.
# """
# from django.contrib import admin
# from django.urls import path, include
# from django.views.generic import TemplateView
# from django.conf import settings
# from django.conf.urls.static import static

# urlpatterns = [
#     path('admin/', admin.site.urls),
#     # Registry App Namespace
#     path('registry/', include('registry.urls')),
#     # Render the base template for the root homepage to display the beautiful layout, branding, and colors
#     path('', TemplateView.as_view(template_name='base.html'), name='home'),
# ]

# # Serve media and static files in development
# if settings.DEBUG:
#     urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
#     urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)    