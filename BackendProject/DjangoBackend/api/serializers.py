from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework import status
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.core.mail import send_mail
from django.conf import settings
import jwt
from django.contrib.auth import authenticate

from rest_framework import serializers
from django.contrib.auth import authenticate

class UserSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(username=data['username'], password=data['password'])

        if not user:
            raise serializers.ValidationError('Invalid credentials. Please try again.')

        data['user'] = user
        return data

class RegisterSerializer(serializers.ModelSerializer):
  
  password = serializers.CharField(
    write_only=True, required=True, validators=[validate_password])
  confirm_password = serializers.CharField(write_only=True, required=True)
  class Meta:
    model = User
    fields = ('username', 'first_name', 'last_name', 'password', 'confirm_password',
          )
    extra_kwargs = {
      'first_name': {'required': True},
      'last_name': {'required': True}
    }
  def validate(self, attrs):
    if attrs['password'] != attrs['confirm_password']:
      raise serializers.ValidationError(
        {"password": "Password fields didn't match."})
    return attrs
  def create(self, validated_data):
    user = User.objects.create(
      username=validated_data['username'],
     
      first_name=validated_data['first_name'],
      last_name=validated_data['last_name']
    )
    user.set_password(validated_data['password'])
    token = jwt.encode({'user_id': user.id}, settings.SECRET_KEY, algorithm='HS256')
    send_mail(
            'Account Verification',
            f'Click the following link to verify your email: http://localhost:3000/login?token={token}',
            settings.EMAIL_HOST_USER,
            [user.username],
            fail_silently=False,
        )
    
    user.save()
    return user

class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, value):
        try:
            payload = jwt.decode(value, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            user.is_active = True
            user.save()
            return value
        except jwt.ExpiredSignatureError:
            raise serializers.ValidationError('Verification link has expired.')
        except jwt.exceptions.DecodeError:
            raise serializers.ValidationError('Invalid verification token.')
        except User.DoesNotExist:
            raise serializers.ValidationError('User not found.')  