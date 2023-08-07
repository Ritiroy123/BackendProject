from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from rest_framework.permissions import AllowAny
from api.serializers import RegisterSerializer,EmailVerificationSerializer
from django.contrib.auth import get_user_model
from rest_framework.authentication import TokenAuthentication
from rest_framework import generics
from django.shortcuts import redirect
from django.urls import reverse
from django.http import JsonResponse
import requests
from rest_framework.generics import UpdateAPIView
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from api.serializers import UserLoginSerializer,SendPasswordResetEmailSerializer, UserPasswordChangeSerializer, UserPasswordResetSerializer,workInfoSerializer
from django.contrib.auth import authenticate
from rest_framework.parsers import MultiPartParser, FormParser
#from .models import Profile
#from .serializers import ProfileSerializer
from .serializers import CustomUserSerializer
from .models import checklist
User = get_user_model()


class UserProfilePictureView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def get(self, request, *args, **kwargs):
        # Get the profile picture of the authenticated user
        try:
            user = User.objects.get(pk=request.user.pk)
            serializer = CustomUserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

    def post(self, request, *args, **kwargs):
        # Update the profile picture of the authenticated user
        try:
            user = User.objects.get(pk=request.user.pk)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        # Update the profile picture with the request data
        serializer = CustomUserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }
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
class UserLoginView(APIView):
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)
      return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'login failed.'}, status=status.HTTP_404_NOT_FOUND)
    

@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Registered success.'}, status=status.HTTP_201_CREATED)
        return Response({'message': 'Email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def verify_email(request):
    if request.method == 'POST':
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    
    


class APIChangePasswordView(UpdateAPIView):
    serializer_class = UserPasswordChangeSerializer
    model = User # your user model
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        return self.request.user
class SendPasswordResetEmailView(APIView):
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)
  






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




class workInfoView(APIView):
  
  def get(self,request,*args, **kwargs):
        # Get the value  of the authenticated user
        try:
            checklists = checklist.objects.all()
            serializer = workInfoSerializer(checklists, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

      
  def post(self, request,*args, **kwargs):
      
      print(request.data)
      checklists = checklist.objects.all()
      serializer = workInfoSerializer(data=request.data)
      if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
      else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
      
#b=User(email="riti2345679@gmail.com",name="riti",phone_number="93546737")   
#b.save()
#a = checklist(project_name="qq",project_name1="a",project_location="a",project_location1="a",supervisor_name="q", subcontractor_name="a",work_start_date="2023-08-07",work_start_date1="2023-08-07",work_completion_date="2023-08-07",work_completion_date1="2023-08-07",wcp_esic_verification="Yes",aadhar_card_verification="Yes",before_entry_body_scanning="Yes",before_entry_bag_check="Yes",physical_appearance="Yes",before_entry_bag_tales_and_tool_check="Yes",before_entry_bag_mental_health_check="Yes",physical_health_check="Yes",before_entry_bag_behavioral_check="Yes",before_entry_bag_safety_helmet_check="Yes",before_entry_bag_safety_shoes_check="Yes",before_entry_bag_safety_jackets_check="Yes",ladders_health_check="Yes",work_place_check="Yes",work_place_cleanliness_check="Yes",balance_material_on_specified_area_check="Yes",ladders_placement_check="Yes",before_exit_body_scanning="Yes",before_exit_bag_check="Yes",before_exit_bag_tales_and_tool_check="Yes",before_exit_bag_mental_health_check="Yes",before_exit_bag_behavioral_check="Yes",before_exit_bag_safety_helmet_check="Yes",before_exit_bag_safety_shoes_check="Yes",before_exit_bag_safety_jackets_check="Yes",remark="ddd",user=b)
#a =checklist.objects.filter(duplicate_id=0).count()
#a= checklist.objects.get(pk = 1)
#a.save()
#print(b)
#a=checklist.objects.all()
#print(a)