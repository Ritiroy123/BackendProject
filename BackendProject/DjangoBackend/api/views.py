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
from django.shortcuts import redirect
from django.urls import reverse
from django.http import JsonResponse
import requests
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken

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
@api_view(['POST'])
def user_login(request):
    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)

            response_data = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }

            return Response(response_data)

        return Response(serializer.errors,status=400)

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




def webex_login(request):
    authorize_url = f"{settings.WEBEX_AUTHORIZATION_URL}?client_id={settings.WEBEX_CLIENT_ID}&response_type=code&redirect_uri={settings.WEBEX_REDIRECT_URI}&scope=spark%3Aall%20spark%3Akms"
    return JsonResponse({'url': authorize_url})

def webex_callback(request):
    code = request.GET.get('code')
    access_token_response = requests.post(
        settings.WEBEX_ACCESS_TOKEN_URL,
        data={
            'grant_type': 'authorization_code',
            'client_id': settings.WEBEX_CLIENT_ID,
            'client_secret': settings.WEBEX_CLIENT_SECRET,
            'code': code,
            'redirect_uri': settings.WEBEX_REDIRECT_URI,
        }
    )

    if access_token_response.status_code == 200:
        access_token_data = access_token_response.json()
        access_token = access_token_data['access_token']
        # Handle the access_token, store it in session, or authenticate the user
        # For example:
        # request.session['access_token'] = access_token
        # or
        # Authenticate the user based on the access_token

        return JsonResponse({'message': 'Authentication successful.'})

    return JsonResponse({'error': 'Authentication failed.'}, status=400)