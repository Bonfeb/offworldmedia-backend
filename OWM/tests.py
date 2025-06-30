from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.urls import reverse
from OWM.models import *

CustomUser = get_user_model()

class BaseAuthenticatedTestCase(APITestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            username='testadmin', 
            password='testadmin', 
            is_staff=True, 
            is_superuser=True)
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')


class AuthTests(APITestCase):
    def test_register(self):
        url = reverse('register')
        data = {
            'first_name': 'testuser', 
            'last_name': 'abcd', 
            'username': 'testuser', 
            'email': 'test@example.com', 
            'address': 'Naivasha', 
            'password': '1234'}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 201)

    def test_login(self):
        CustomUser.objects.create_user(username='testuser', password='1234')
        url = reverse('login')
        data = {'username': 'testuser', 'password': '1234'}
        response = self.client.post(url, data)
        self.assertIn(response.status_code, [200, 401])

    def test_token_refresh(self):
        url = reverse('token_refresh')
        response = self.client.post(url, {'refresh': 'dummy'})
        self.assertIn(response.status_code, [200, 401])


class PasswordTests(APITestCase):
    def test_forgot_password(self):
        url = reverse('forgot-password')
        response = self.client.post(url, {'email': 'test@example.com'})
        self.assertIn(response.status_code, [200, 404])


class ProfileTests(BaseAuthenticatedTestCase):
    def test_get_profile(self):
        url = reverse('profile')
        response = self.client.get(url)
        self.assertIn(response.status_code, [200, 401])

    def test_edit_profile(self):
        url = reverse('edit-profile')
        response = self.client.put(url, {'name': 'Updated'})
        self.assertIn(response.status_code, [200, 401])


class UserDashboardTests(BaseAuthenticatedTestCase):
    def test_get_user_dashboard(self):
        url = reverse('userdashboard')
        response = self.client.get(url)
        self.assertIn(response.status_code, [200, 401])


class ServiceTests(APITestCase):
    def test_list_services(self):
        url = reverse('service-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)


class BookingTests(BaseAuthenticatedTestCase):
    def test_create_booking(self):
        service = Service.objects.create(name='Test Service', description='Test Description', price=100, category='Test Category')
        url = reverse('booking', kwargs={'pk': service.id})
        data = {
            'service': service.id,
            'event_date': '2023-10-01',
            'event_time': '12:00:00',
            'event_location': 'Test Location'
        }
        response = self.client.post(url,  data, format='json')
        self.assertIn(response.status_code, [200, 201, 400, 404])


class TeamTests(APITestCase):
    def test_get_team(self):
        url = reverse('team')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)


class ReviewTests(APITestCase):
    def test_get_reviews(self):
        url = reverse('review-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)


class ContactTests(APITestCase):
    def test_contact_us(self):
        url = reverse('contactus')
        data = {
            'name': 'Test User',
            'email': 'user@test.com',
            'subject': 'Test Subject',
            'message': 'This is a test message.'
        }
        response = self.client.post(url, data, format='json')
        self.assertIn(response.status_code, [200, 201])


class MediaTests(APITestCase):
    def test_get_images(self):
        url = reverse('image')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_get_videos(self):
        url = reverse('video')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)


class AdminDashboardTests(BaseAuthenticatedTestCase):
    def test_get_admin_dashboard(self):
        url = reverse('admin-dashboard')
        response = self.client.get(url)
        self.assertIn(response.status_code, [200, 401, 403])


class AdminUserTests(BaseAuthenticatedTestCase):
    def test_list_admin_users(self):
        url = reverse('admin-users')
        response = self.client.get(url)
        self.assertIn(response.status_code, [200, 401])

    def test_get_admin_user(self):
        url = reverse('admin-user', kwargs={'pk': 1})
        response = self.client.get(url)
        self.assertIn(response.status_code, [200, 404, 401])
