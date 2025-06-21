import django_filters
from .models import *

class CustomUserFilter(django_filters.FilterSet):
    username = django_filters.CharFilter(lookup_expr='icontains')
    email = django_filters.CharFilter(lookup_expr='icontains')

    class Meta:
        model = CustomUser
        fields = ['username', 'email']

class BookingFilter(django_filters.FilterSet):
    username = django_filters.CharFilter(field_name='user__username', lookup_expr='icontains')
    service = django_filters.CharFilter(field_name='service__name', lookup_expr='icontains')
    event_location = django_filters.CharFilter(lookup_expr='icontains')
    status = django_filters.CharFilter(lookup_expr='iexact')

    class Meta:
        model = Booking
        fields = ['username', 'service', 'event_location', 'status']

class ReviewFilter(django_filters.FilterSet):
    username = django_filters.CharFilter(field_name='user__username', lookup_expr='icontains')
    service = django_filters.CharFilter(field_name='service___name', lookup_expr='icontains')

    class Meta:
        model = Review
        fields = ['username', 'service']

class TeamMemberFilter(django_filters.FilterSet):
    role = django_filters.CharFilter(lookup_expr='icontains')
    name = django_filters.CharFilter(lookup_expr='icontains')

    class Meta:
        model = TeamMember
        fields = ['role', 'name']

class ContactUsFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(lookup_expr='icontains')
    email = django_filters.CharFilter(lookup_expr='icontains')
    status = django_filters.CharFilter(lookup_expr='icontains')

    class Meta:
        model = ContactUs
        fields = ['name', 'email', 'status']
