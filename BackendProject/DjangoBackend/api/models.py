from django.db import models
from django.contrib.auth.models import BaseUserManager,AbstractBaseUser
from django.utils import timezone
#from api.models import User





#  Custom User Manager
class UserManager(BaseUserManager):
  def create_user(self, email, name, phone_number,  password=None, password2=None):
      """
      Creates and saves a User with the given email, name, tc and password.
      """
      if not email:
          raise ValueError('User must have an email address')

      user = self.model(
          email=self.normalize_email(email),
          name=name,
          phone_number=phone_number,
          
      )

      user.set_password(password)
      user.save(using=self._db)
      return user

  def create_superuser(self, email, name, phone_number,  password=None):
      
      """
      Creates and saves a superuser with the given email, name, tc and password.

      """
      
        
      user = self.create_user(
          email,
          password=password,
          name=name,
          phone_number=phone_number,
        
          
      )
      user.is_admin = True
      user.save(using=self._db)
      return user

#  Custom User Model
class User(AbstractBaseUser):
  email = models.EmailField(
      verbose_name='Email',
      max_length=255,
      unique=True,
  )
  name = models.CharField(max_length=200)
  phone_number =models.CharField(max_length=12)
  profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
  project_name = models.TextField(blank=True)
  project_site = models.TextField(blank=True)
  sub_contractor = models.TextField(blank=True)
  first_name = models.TextField(blank=True)
  middle_name = models.TextField(blank=True)
  last_name = models.TextField(blank=True)
  date = models.DateField(default=timezone.now)
  work_start_time = models.DateField(default=None)
  bag_check_done_on_entry = models.BooleanField(default=False)
  fit_to_work_physical_health = models.BooleanField(default=False)
  fit_to_work_mind = models.BooleanField(default=False)
  dressed_properly = models.BooleanField(default=False)
  meeting_site_safety_requirements = models.BooleanField(default=False)
  work_end_time = models.DateField(default=None)
  bag_check_done_on_exit = models.BooleanField(default=False)
  safety_shoes = models.BooleanField(default=False)
  safety_jacket = models.BooleanField(default=False)
  safety_helmet = models.BooleanField(default=False)
  is_active = models.BooleanField(default=True)
  is_admin = models.BooleanField(default=False)
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)

  objects = UserManager()

  USERNAME_FIELD = 'email'
  REQUIRED_FIELDS = ['name', 'phone_number']

  def __str__(self):
      return self.email

  def has_perm(self, perm, obj=None):
      "Does the user have a specific permission?"
      # Simplest possible answer: Yes, always
      return self.is_admin

  def has_module_perms(self, app_label):
      "Does the user have permissions to view the app `app_label`?"
      # Simplest possible answer: Yes, always
      return True

  @property
  def is_staff(self):
      "Is the user a member of staff?"
      # Simplest possible answer: All admins are staff
      return self.is_admin
  

  


  
