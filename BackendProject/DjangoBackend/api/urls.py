from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from . import views

from .views import register_user, verify_email,user_login
from .views import webex_login, webex_callback



#from .views import WebexOpenIDCallbackView









urlpatterns = [
   
    
    path('logout/', views.LogoutView.as_view(), name ='logout') , 


    path('login/', user_login, name='user_login'),
  # path('register',RegisterUser.as_view()),
     path('home/', views.HomeView.as_view(), name ='home'),
     path('register/', register_user, name='register_user'),
    path('verify/', verify_email, name='verify_email'),
      path('webex/login/', webex_login, name='webex_login'),
    path('webex/callback/', webex_callback, name='webex_callback'),
   

]
