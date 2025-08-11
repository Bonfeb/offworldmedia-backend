from cloudinary_storage.storage import MediaCloudinaryStorage
import requests
import json
from requests.auth import HTTPBasicAuth
from django.conf import settings
from django.template.loader import render_to_string
from django.templatetags.static import static
from weasyprint import HTML
from django.http import HttpResponse
import re,os
import datetime
import random
from .models import *
from .filters import *

request = ""

class VideoMediaCloudinaryStorage(MediaCloudinaryStorage):
    def get_options(self, name):
        options = super().get_options(name)
        options['resource_type'] = 'video'
        return options

def get_access_token():
    consumer_key = settings.CONSUMER_KEY
    consumer_secret = settings.CONSUMER_SECRET
    api_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    
    try:
        response = requests.get(
            api_url,
            auth=HTTPBasicAuth(consumer_key, consumer_secret)
        )
        if response.status_code == 200:
            mpesa_access_token = response.json()
            mpesa_token = mpesa_access_token.get('access_token')

            if mpesa_token:
                print("Access Token Received:", mpesa_token)
                return mpesa_token
            else:
                print("❌ Access token not found in response JSON.")
                print("🔍 Full response JSON:", mpesa_access_token)
                return None
        else:
            print(f"❌ Failed to get token: {response.status_code}")
            print(f"🔍 Response Content: {response.text}")
            return None
        
    except requests.RequestException as e:
        print(f"Error fetching access token: {e}")
        return None

def format_mpesa_phone_number(phone_number):
    """
    Convert phone number to M-Pesa format (2547XXXXXXXX)
    Accepts formats: 
    - 07XXXXXXXX (10 digits)
    - +2547XXXXXXXX (13 characters with +)
    - 2547XXXXXXXX (12 digits)
    - 7XXXXXXXX (9 digits)
    
    Returns:
        str: Phone number in 2547XXXXXXXX format
        
    Raises:
        ValueError: If phone number format is invalid
    """
    if not phone_number or not isinstance(phone_number, str):
        raise ValueError("Phone number must be a non-empty string")
    
    # Remove all non-digit characters
    cleaned = re.sub(r'[^0-9]', '', phone_number)
    
    # Validate the cleaned number
    if len(cleaned) < 9 or len(cleaned) > 12:
        raise ValueError("Phone number must be between 9 and 12 digits after cleaning")
    
    # Conversion logic
    if cleaned.startswith('254') and len(cleaned) == 12:
        # Already in correct format (2547XXXXXXXX)
        formatted = cleaned
    elif cleaned.startswith('0') and len(cleaned) == 10:
        # Convert from 07XXXXXXXX to 2547XXXXXXXX
        formatted = '254' + cleaned[1:]
    elif len(cleaned) == 9 and cleaned.startswith('7'):
        # Convert from 7XXXXXXXX to 2547XXXXXXXX
        formatted = '254' + cleaned
    elif cleaned.startswith('254') and len(cleaned) == 13:
        # Handle case where original had + (like +254712345678)
        formatted = cleaned
    else:
        raise ValueError(
            "Invalid phone number format. "
            "Use 07..., +2547..., 2547..., or 7..."
        )
    
    # Final validation
    if not re.fullmatch(r'2547\d{8}', formatted):
        raise ValueError("Resulting phone number format is invalid (must be 2547XXXXXXXX)")
    
    return formatted

def generate_invoice_number():
    date_str = datetime.datetime.now().strftime('%Y%m%d')
    unique_id = random.randint(100000, 999999)
    
    return f"INV-{date_str}-{unique_id}"

def generate_users_pdf(request):
    try:
        # Start with all non-staff, non-superuser users
        users = CustomUser.objects.filter(is_staff=False, is_superuser=False)

        # Apply filters from query params
        username = request.GET.get('username')
        if username:
            users = users.filter(username__icontains=username)

        email = request.GET.get('email')
        if email:
            users = users.filter(email__icontains=email)

        # If you already have a DRF/Django FilterSet, use it instead
        # users = CustomUserFilter(request.GET, queryset=users).qs

        # Order the queryset
        users = CustomUserFilter(request.GET, queryset=users).qs.order_by('username')

        if not users.exists():
            return HttpResponse("No users found", status=404)
        
        logo_path = os.path.join(settings.STATIC_ROOT, 'images', 'Logo.ico')
        logo_url = f'file://{logo_path}' if os.path.exists(logo_path) else static('images/Logo.ico')

        context = {
            'pdf_users': users,
            'total_users': users.count(),
            'company_name': 'Offworld Media Africa',
            'company_email': 'offworldmediaafrica@gmail.com',
            'company_x': 'offworldmedia_africa',
            'company_facebook': 'Offworld Media Africa',
            'company_youtube': 'Offworld Media Africa',
            'generation_date': datetime.datetime.now().strftime('%B %d, %Y at %H:%M'),
            'logo_url': logo_url,
        }

        html_string = render_to_string('users_pdf.html', context)
        html_pdf = HTML(string=html_string, base_url=request.build_absolute_uri()).write_pdf()
        

        filename = f"Offworld_Media_Users_{datetime.datetimenow().strftime('%Y%m%d_%H%M%S')}.pdf"

        response = HttpResponse(html_pdf, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    except Exception as e:
        print(f"Error generating PDF: {e}")
        return HttpResponse("Error generating PDF", status=500)

def filter_bookings(params):
    """
    Applies filtering for bookings based on query parameters.
    This ensures JSON and PDF downloads return the same filtered results.
    """
    queryset = Booking.objects.select_related('user', 'service')

    # Status filter
    status_filter = params.get('status')
    if status_filter and status_filter.lower() != 'all':
        queryset = queryset.filter(status=status_filter.lower())

    # Username filter
    username = params.get('username')
    if username:
        queryset = queryset.filter(user__username__icontains=username)

    # Event location filter
    event_location = params.get('event_location')
    if event_location:
        queryset = queryset.filter(event_location__icontains=event_location)

    # Event date filter (exact match)
    event_date = params.get('event_date')
    if event_date:
        queryset = queryset.filter(event_date=event_date)

    return queryset.order_by('user__username', '-event_date', '-event_time')

def generate_bookings_pdf(request, queryset, status_filter='All'):
    """
    Generate PDF from a queryset of bookings.
    Returns an HttpResponse with the PDF file.
    """
    if not queryset.exists():
        return HttpResponse("No bookings found", status=404)
    
    logo_path = os.path.join(settings.STATIC_ROOT, 'images', 'Logo.ico')
    logo_url = f'file://{logo_path}' if os.path.exists(logo_path) else static('images/Logo.ico')

    context = {
        'pdf_bookings': queryset,
        'total_bookings': queryset.count(),
        'status_filter': status_filter,
        'company_name': 'Offworld Media Africa',
        'company_email': 'offworldmediaafrica@gmail.com',
        'company_x': 'offworldmedia_africa',
        'company_facebook': 'Offworld Media Africa',
        'company_youtube': 'Offworld Media Africa',
        'generation_date': datetime.datetime.now().strftime('%B %d, %Y at %H:%M'),
        'logo_url': logo_url,
    }

    html_string = render_to_string('bookings_pdf.html', context)
    pdf_content = HTML(string=html_string, base_url=request.build_absolute_uri()).write_pdf()

    filename = f"Offworld_Media_Bookings_{status_filter}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    response = HttpResponse(pdf_content, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response