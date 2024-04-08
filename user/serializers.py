from rest_framework import serializers
from .models import User

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import DjangoUnicodeDecodeError, force_bytes, smart_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from .utils import Utils


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = [
            'email',
            'name',
            'tc',
            'password',
            'password2'
        ]
        extra_kwargs={
            'password': {'write_only': True}
        }

    # validating Password and Confirm Password while Registration
    def validate(self, attrs):
        password = attrs['password']
        password2 = attrs['password2']
        if password != password2:
            raise serializers.ValidationError('Password does not match!')
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = [
            'email',
            'password'
        ]


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'name',
            'tc'
        ]


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = [
            'password',
            'password2'
        ]

    def validate(self, attrs):
        user = self.context['user']
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError('Password and confirm Password does not match!')
        user.set_password(attrs['password'])
        user.save()
        return attrs


class UserResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('UID:', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Token:', token)
            link = 'http://localhost/reset-password/'+uid+'/'+token
            print('link:', link)

            # Send Email
            data = {
                'subject': 'Reset Your Password',
                'body': 'Click following link to reset your Password: ' + link,
                'email_to': user.email
            }
            Utils.send_email(data)
            return attrs
        raise serializers.ValidationError('You are not a Registered User')


class UserResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = [
            'password',
            'password2'
        ]

    def validate(self, attrs):
        try:
            if attrs['password'] != attrs['password2']:
                raise serializers.ValidationError('Password and confirm Password does not match!')
            uid = self.context['uid']
            token = self.context['token']
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError({'message': 'Token is not Valid or Expired'})
            user.set_password(attrs['password'])
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as e:
            PasswordResetTokenGenerator().check_token(user, token)
            return {'message': 'Something went wrong', 'error': e}
