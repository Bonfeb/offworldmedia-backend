from cloudinary_storage.storage import MediaCloudinaryStorage
import requests, json
from requests.auth import HTTPBasicAuth
from django.conf import settings

request = ""

class VideoMediaCloudinaryStorage(MediaCloudinaryStorage):
    def get_options(self, name):
        options = super().get_options(name)
        options['resource_type'] = 'video'
        return options

def get_access_token(request):
    consumer_key = settings.CONSUMER_KEY
    consumer_secret = settings.CONSUMER_SECRET
    api_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    r = requests.get(
        api_url,
        auth=HTTPBasicAuth(consumer_key, consumer_secret))
    mpesa_access_token = json.loads(r.text)
    validated_mpesa_access_token = mpesa_access_token['access_token']

    print(validated_mpesa_access_token)

get_access_token(request)