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
  #profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
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
  

class checklist(models.Model):
    project_name = models.TextField(blank=False,null=False)
    project_name1 = models.TextField(default=None,blank=False,null=False)
    project_location = models.TextField(blank=False,null=False)
    project_location1 = models.TextField(default=None,blank=True,null=False)
    supervisor_name = models.TextField(blank=False,null=False)
    subcontractor_name = models.TextField(blank=False,null=False)
    work_start_date = models.DateField(default=None,null=False)
    work_start_date1 = models.DateField(default=None,null=False)
    work_completion_date = models.DateField(default=None,null=False)
    work_completion_date1 = models.DateField(default=None,null=False)
    wcp_esic_verification_status = models.TextField(blank=False,null=False)
    wcp_esic_verification = models.TextField(blank=False,null=False)
    aadhar_card_verification_status = models.TextField(default=None,blank=True,null=False)
    aadhar_card_verification = models.TextField(default=None,blank=True,null=False)
    before_entry_body_scanning_status = models.TextField(blank=False,null=False)
    before_entry_body_scanning = models.TextField(blank=False,null=False)
    before_entry_bag_check_status = models.TextField(blank=False,null=False)
    before_entry_bag_check = models.TextField(blank=False,null=False)
    physical_appearance_status = models.TextField(blank=False,null=False)
    physical_appearance = models.TextField(blank=False,null=False)
    before_entry_bag_tales_and_tool_check_status = models.TextField(blank=False,null=False)
    before_entry_bag_tales_and_tool_check = models.TextField(blank=False,null=False)
    before_entry_bag_mental_health_check_status = models.TextField(blank=False,null=False)
    before_entry_bag_mental_health_check = models.TextField(blank=False,null=False)
    physical_health_check_status = models.TextField(blank=False,null=False)
    physical_health_check = models.TextField(blank=False,null=False)
    before_entry_bag_behavioral_check_status = models.TextField(blank=False,null=False)
    before_entry_bag_behavioral_check = models.TextField(blank=False,null=False)
    before_entry_bag_safety_helmet_check_status = models.TextField(blank=False,null=False)
    before_entry_bag_safety_helmet_check = models.TextField(blank=False,null=False)
    before_entry_bag_safety_shoes_check_status = models.TextField(blank=False,null=False)
    before_entry_bag_safety_shoes_check = models.TextField(blank=False,null=False)
    before_entry_bag_safety_jackets_check_status = models.TextField(blank=False,null=False)
    before_entry_bag_safety_jackets_check = models.TextField(blank=False,null=False)
    ladders_health_check_status = models.TextField(blank=False,null=False)
    ladders_health_check = models.TextField(blank=False,null=False)
    work_place_check_status= models.TextField(blank=False,null=False)
    work_place_check = models.TextField(blank=False,null=False)
    work_place_cleanliness_check_status = models.TextField(blank=False,null=False)
    work_place_cleanliness_check = models.TextField(blank=False,null=False)
    balance_material_on_specified_area_check_status = models.TextField(blank=False,null=False)
    balance_material_on_specified_area_check = models.TextField(blank=False,null=False)
    ladders_placement_check_status = models.TextField(blank=False,null=False)
    ladders_placement_check = models.TextField(blank=False,null=False)
    before_exit_body_scanning_status = models.TextField(blank=False,null=False)
    before_exit_body_scanning = models.TextField(blank=False,null=False)
    before_exit_bag_check_status = models.TextField(blank=False,null=False)
    before_exit_bag_check = models.TextField(blank=False,null=False)
    before_exit_bag_tales_and_tool_check_status = models.TextField(blank=False,null=False)
    before_exit_bag_tales_and_tool_check = models.TextField(blank=False,null=False)
    before_exit_bag_mental_health_check_status = models.TextField(blank=False,null=False)
    before_exit_bag_mental_health_check = models.TextField(blank=False,null=False)
    before_exit_bag_behavioral_check_status = models.TextField(blank=False,null=False)
    before_exit_bag_behavioral_check = models.TextField(blank=False,null=False)
    before_exit_bag_safety_helmet_check_status = models.TextField(blank=False,null=False)
    before_exit_bag_safety_helmet_check = models.TextField(blank=False,null=False)
    before_exit_bag_safety_shoes_check_status = models.TextField(blank=False,null=False)
    before_exit_bag_safety_shoes_check = models.TextField(blank=False,null=False)
    before_exit_bag_safety_jackets_check_status = models.TextField(blank=False,null=False)
    before_exit_bag_safety_jackets_check = models.TextField(blank=False,null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    auto_increment_id = models.AutoField(primary_key=True,default=False)
    user = models.ForeignKey(User,on_delete=models.CASCADE,blank=True,null=True)



  


  
