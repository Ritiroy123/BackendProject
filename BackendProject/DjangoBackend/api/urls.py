from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from . import views
from .views import register_user, verify_email
from .views import webex_login, webex_callback
from api.views import SendPasswordResetEmailView, APIChangePasswordView, UserPasswordResetView,UserLoginView, workInfoView
from rest_framework_simplejwt.views import TokenRefreshView
#from .views import ImageUploadView


#from .views import WebexOpenIDCallbackView
#from .views import ProfileView
from .views import UserProfilePictureView



   

urlpatterns = [ 
    path('logout/', views.LogoutView.as_view(), name ='logout') , 
     path('login/', UserLoginView.as_view(), name='login'),
     path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
  # path('register',RegisterUser.as_view()),
     path('home/', views.HomeView.as_view(), name ='home'),
     path('register/', register_user, name='register_user'),
    path('verify/', verify_email, name='verify_email'),
      path('webex/login/', webex_login, name='webex_login'),
    path('webex/callback/', webex_callback, name='webex_callback'),
    path('changepassword/', APIChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
   #  path('upload/', ImageUploadView.as_view(), name='image-upload'),
   # path('profile/', ProfileView.as_view(), name='profile'),
   # path('profile/', ProfileView.as_view(), name='profile'),
    path('upload/', UserProfilePictureView.as_view(), name='user_profile_picture'),
    path('info/', workInfoView.as_view(), name='work_Info_View'),
     path('getinfo/', views.workget, name='work_Info_View'),

]

