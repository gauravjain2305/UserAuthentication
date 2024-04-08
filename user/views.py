from django.contrib.auth import authenticate
from rest_framework.response import Response
from rest_framework import permissions, views

from .serializers import *

from rest_framework_simplejwt.tokens import RefreshToken

# Generate Token manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# Create your views here.

class UserRegistrationView(views.APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({
                'message': 'User registration successful',
                'token': token
            })


class UserLoginView(views.APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            user = authenticate(
                email=serializer.data['email'],
                password=serializer.data['password']
            )
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({
                    'message': 'Login successful',
                    'token': token
                })
        return Response({'message': 'Incorrect email or password'})


class UserProfileView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


class UserChangePasswordView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'message': 'Password change successful'})


class UserResetPasswordEmailView(views.APIView):
    def post(self, request):
        serializer = UserResetPasswordEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'message': 'Password reset link sent. Please check your Email.'})


class UserResetPasswordView(views.APIView):
    def post(self, request, uid, token):
        serializer = UserResetPasswordSerializer(data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid(raise_exception=True):
            return Response({'message': 'Password reset successful'})
