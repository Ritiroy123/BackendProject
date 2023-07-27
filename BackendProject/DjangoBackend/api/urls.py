from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from . import views

from .views import register_user, verify_email
from .views import webex_login, webex_callback
from api.views import SendPasswordResetEmailView, UserChangePasswordView, UserPasswordResetView,UserLoginView
from rest_framework_simplejwt.views import TokenRefreshView


#from .views import WebexOpenIDCallbackView

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
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),

]
