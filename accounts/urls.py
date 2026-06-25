from django.urls import path

from .views import FamilySignUpView

urlpatterns = [
    path('signup/', FamilySignUpView.as_view(), name='signup'),
]

