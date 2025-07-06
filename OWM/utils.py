from cloudinary_storage.storage import MediaCloudinaryStorage
import requests
import json
from requests.auth import HTTPBasicAuth
from django.conf import settings
import re

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
            access_token = mpesa_access_token.get('access_token')

            if access_token:
                print("Access Token:", access_token)
                return access_token
            else:
                print("Access token not found in response.")
                return None
        else:
            print(f"Failed to get access token: {response.status_code} - {response.text}")
            return None
        
    except requests.RequestException as e:
        print(f"Error fetching access token: {e}")
        return None
            
get_access_token()

def format_mpesa_phone_number(phone_number):
    """
    Convert phone number to M-Pesa format (2547XXXXXXXX)
    Accepts formats: 07XXXXXXXX, +2547XXXXXXXX, 2547XXXXXXXX
    """
    # Remove all non-digit characters
    cleaned = re.sub(r'[^0-9]', '', phone_number)
    
    if cleaned.startswith('0') and len(cleaned) == 10:
        # Convert 07XXXXXXXX to 2547XXXXXXXX
        return '254' + cleaned[1:]
    elif cleaned.startswith('254') and len(cleaned) == 12:
        # Already in correct format
        return cleaned
    elif len(cleaned) == 9 and not cleaned.startswith('0'):
        # Handle 7XXXXXXXX case
        return '254' + cleaned
    else:
        raise ValueError("Invalid phone number format")