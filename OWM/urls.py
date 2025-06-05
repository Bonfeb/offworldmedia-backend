from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import *

urlpatterns = [
    # Auth Endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('forgot-password/', ForgotPasswordView.as_view(), name="forgot-password"),
    path('reset-password/<str:uidb64>/<str:token>/', ResetPasswordView.as_view(), name="reset-password"),
    path('change-password/', ChangePasswordView.as_view(), name="change-password"),
    #path('token/refresh/', CookieTokenRefreshView.as_view, name='token_refresh'),

    #Profile Endpoint
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('profile/edit/', UserProfileView.as_view(), name="edit-profile"),

    #Userdashboard Endpoints
    path('userdashboard/', UserDashboardView.as_view(), name="userdashboard"),
    path('userdashboard/<int:pk>/', UserDashboardView.as_view(), name="userdashboard"),

    # Service Endpoints 
    path('services/', ServiceView.as_view(), name='service-list'),
    path('service/', ServiceView.as_view()),
    path('service/<int:pk>/', ServiceView.as_view(), name='service'),
 
    path('bookings/', BookingView.as_view(), name='booking'),
    path('booking/<int:pk>/', BookingView.as_view(), name='booking'),
    
    # TeamMembers Endpoints
    path('team/', TeamListView.as_view(), name='team'),
    path('team/<int:pk>/', TeamView.as_view(), name='team-member'),

    # Review Endpoints
    path('reviews/', ReviewView.as_view(), name='review-list'),
    path('review/<int:pk>', ReviewView.as_view(), name='review'),

    #Contact Endpoints
    path('contactus/', ContactUsView.as_view(), name='contactus'),
    path('contactus/<int:pk>/', ContactUsView.as_view()),

    #Admin Dashboard paths
    path('admin-dashboard/', AdminDashboardView.as_view(), name='admin-dashboard'),
    path('admin-dashboard/<int:pk>/', AdminDashboardView.as_view(), name='admin-dashboard'),
]