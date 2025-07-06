from cloudinary_storage.storage import MediaCloudinaryStorage
import requests
import json
from requests.auth import HTTPBasicAuth
from django.conf import settings

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