from django.urls import path

from .views import *

urlpatterns = [
    path('register/', UserRegistrationView.as_view()),
    path('login/', UserLoginView.as_view()),
    path('profile/', UserProfileView.as_view()),
    path('change-password/', UserChangePasswordView.as_view()),
    path('reset-password-email/', UserResetPasswordEmailView.as_view()),
    path('reset-password/<uid>/<token>/', UserResetPasswordView.as_view())
]
