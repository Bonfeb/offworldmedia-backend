import django_filters
from .models import *

class CustomUserFilter(django_filters.FilterSet):
    class Meta:
        model = CustomUser
        fields = {
            'username': ['icontains'],
            'email': ['icontains'],
        }

class BookingFilter(django_filters.FilterSet):
    class Meta:
        model = Booking
        fields = {
            'event_location': ['icontains'],
            'user': ['exact'],
            'service': ['exact'],
            'status': ['exact'],
        }

class ReviewFilter(django_filters.FilterSet):
    user__username = django_filters.CharFilter(field_name='user__username', lookup_expr='icontains')
    class Meta:
        model = Review
        fields = ['user__username', 'service']

class TeamMemberFilter(django_filters.FilterSet):
    class Meta:
        model = TeamMember
        fields = {
            'role': ['exact'],
            'name': ['icontains'],
        }

class ContactUsFilter(django_filters.FilterSet):
    class Meta:
        model = ContactUs
        fields = {
            'name': ['icontains'],
            'email': ['icontains'],
            'status': ['exact'],
        }
