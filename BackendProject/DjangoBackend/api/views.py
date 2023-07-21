from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from rest_framework.decorators import api_view, permission_classes

from rest_framework import status

from rest_framework.permissions import AllowAny
from api.serializers import UserSerializer,RegisterSerializer,EmailVerificationSerializer
from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication
from rest_framework import generics
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.providers.oauth2.views import OAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
import json
import requests
from openid.consumer import consumer

from allauth.socialaccount.models import SocialAccount
from allauth.socialaccount.providers.openid.views import (
    OpenIDAdapter, OpenIDCallbackView
)
from allauth.socialaccount.providers.openid.client import OpenIDClient

class WebexOpenIDClient(OpenIDClient):
    def get_id_token_data(self, response):
        return json.loads(response.content)

class WebexOpenIDAdapter(OpenIDAdapter):
    client_class = WebexOpenIDClient

webex_openid_callback = WebexOpenIDAdapter()

class WebexOpenIDCallbackView(OpenIDCallbackView):
    def dispatch(self, request, *args, **kwargs):
        # Handle the successful login here and obtain the user data from the ID token.
        # You can save the user data to the Django user model or use it as needed.
        return super().dispatch(request, *args, **kwargs)










# Create your views here.

class HomeView(APIView):
     
   permission_classes = (IsAuthenticated, )
   def get(self, request):
       content = {'message': 'Welcome to the JWT Authentication page using React Js and Django!' }
                   
       return Response(content) 
   


class LogoutView(APIView):
     permission_classes = (IsAuthenticated,)
     def post(self, request):
          
          try:
               refresh_token = request.data["refresh_token"]
               token = RefreshToken(refresh_token)
               token.blacklist()
               return Response(status=status.HTTP_205_RESET_CONTENT)
          except Exception as e:
               return Response(status=status.HTTP_400_BAD_REQUEST)
          


# Class based view to Get User Details using Token Authentication
class UserDetailAPI(APIView):
  authentication_classes = (TokenAuthentication,)
  permission_classes = (AllowAny,)
  def get(self,request,*args,**kwargs):
    user = User.objects.get(id=request.user.id)
    serializer = UserSerializer(user)
    return Response(serializer.data)



@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


@api_view(['POST'])
def verify_email(request):
    if request.method == 'POST':
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    




