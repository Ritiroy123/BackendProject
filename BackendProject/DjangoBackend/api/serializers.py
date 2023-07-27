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
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator


class UserSerializer(serializers.ModelSerializer):
  username = serializers.CharField(max_length=255)
  class Meta:
    model = User
    fields = ['username', 'password']

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
        


class UserChangePasswordSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  confirm_password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'confirm_password']

  def validate(self, attrs):
    password = attrs.get('password')
    confirm_password = attrs.get('confirm_password')
    user = self.context.get('user')
    if password != confirm_password:
      raise serializers.ValidationError("Password and Confirm Password doesn't match")
    user.set_password(password)
    user.save()
    return attrs    


class SendPasswordResetEmailSerializer(serializers.Serializer):
  username = serializers.CharField(max_length=255)
  class Meta:
    fields = ['username']

  def validate(self, attrs):
    username = attrs.get('username')
    if User.objects.filter(username=username).exists():
      user = User.objects.get(username = username)
      uid = urlsafe_base64_encode(force_bytes(user.id))
      print('Encoded UID', uid)
      token = PasswordResetTokenGenerator().make_token(user)
      print('Password Reset Token', token)
      link = 'http://localhost:3000/forget-password?id='+uid+'&token='+token
      send_mail(
            'Account Verification',
            f'Click Following Link to Reset Your Password '+link,
            settings.EMAIL_HOST_USER,
            [user.username],
            fail_silently=False,
        )
      # Util.send_email(data)
      return attrs
    else:
      raise serializers.ValidationError('You are not a Registered User')      
    

class UserPasswordResetSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  confirm_password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'confirm_password']

  def validate(self, attrs):
    try:
      password = attrs.get('password')
      confirm_password = attrs.get('confirm_password')
      uid = self.context.get('uid')
      token = self.context.get('token')
      if password != confirm_password:
        raise serializers.ValidationError("Password and Confirm Password doesn't match")
      id = smart_str(urlsafe_base64_decode(uid))
      user = User.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise serializers.ValidationError('Token is not Valid or Expired')
      user.set_password(password)
      user.save()
      return attrs
    except DjangoUnicodeDecodeError as identifier:
      PasswordResetTokenGenerator().check_token(user,token)
      raise serializers.ValidationError('Token is not Valid or Expired')
    
    