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
    service = django_filters.CharFilter(field_name='service__category', lookup_expr='icontains')
    event_location = django_filters.CharFilter(lookup_expr='icontains')
    status = django_filters.CharFilter(lookup_expr='iexact')

    class Meta:
        model = Booking
        fields = ['username', 'service', 'event_location', 'status']

class ServiceFilter(django_filters.FilterSet):
    category = django_filters.CharFilter(lookup_expr='icontains')
    audio_category = django_filters.CharFilter(field_name='category__name', lookup_expr='icontains')
    price = django_filters.NumberFilter(lookup_expr='icontains')

    class Meta:
        model = Service
        fields = ['category', 'audio_category', 'price']

class MpesaTransactionFilter(django_filters.FilterSet):
    phone_number = django_filters.CharFilter(lookup_expr='icontains')
    status = django_filters.CharFilter(lookup_expr='iexact')
    booking = django_filters.CharFilter(field_name='booking__id', lookup_expr='exact')

    class Meta:
        model = MpesaTransaction
        fields = ['phone_number', 'status', 'booking']

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
