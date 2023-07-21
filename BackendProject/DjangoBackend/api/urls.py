from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from . import views
from .views import UserDetailAPI
from .views import register_user, verify_email

from .views import WebexOpenIDCallbackView









urlpatterns = [
  
   path('login/', 
          jwt_views.TokenObtainPairView.as_view(), 
          name ='token_obtain_pair'),
   path('token/refresh/', 
          jwt_views.TokenRefreshView.as_view(), 
          name ='token_refresh'),

     
    path('logout/', views.LogoutView.as_view(), name ='logout') , 


    path("get-details",UserDetailAPI.as_view()),
  # path('register',RegisterUser.as_view()),
     path('home/', views.HomeView.as_view(), name ='home'),
     path('register/', register_user, name='register_user'),
    path('verify/', verify_email, name='verify_email'),
      path('webex/openid/callback/', WebexOpenIDCallbackView.as_view(), name='webex_openid_callback'),

]
