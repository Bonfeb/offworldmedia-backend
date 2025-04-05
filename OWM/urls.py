from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import *

urlpatterns = [
    # Auth Endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    #path('token/refresh/', CookieTokenRefreshView.as_view, name='token_refresh'),

    #Profile Endpoint
    path('profile/', UserProfileView.as_view(), name='profile'),

    #Userdashboard Endpoints
    path('userdashboard/', UserDashboardView.as_view(), name="userdashboard"),
    path('userdashboard/<int:pk>/', UserDashboardView.as_view(), name="userdashboard"),

    # Service Endpoints
    path('services/', ServiceView.as_view(), name='service-list'),
    path('service/<int:pk>/', ServiceView.as_view(), name='service'),

    #handles listing all bookings
    path('bookings/', BookingView.as_view(), name='booking-list'),
    
    #handles create, update and delete booking
    path('booking/<int:pk>/', BookingView.as_view(), name='booking'),
    
    # TeamMembers Endpoints
    path('team/', TeamListView.as_view(), name='team'),

    # Review Endpoints
    path('reviews/', ReviewView.as_view(), name='review-list'),
    path('review/<int:pk>', ReviewView.as_view(), name='review'),

    #Contact Endpoints
    path('contactus/', ContactUsView.as_view(), name='contactus'),

    path('test/<int:pk>/', TestView.as_view(), name='test'),

    #Admin Dashboard paths
    path('admin-dashboard/', AdminDashboardView.as_view(), name='admin-dashboard'),
    path('admin-dashboard/<int:pk>/', AdminDashboardView.as_view(), name='admin-dashboard'),
]