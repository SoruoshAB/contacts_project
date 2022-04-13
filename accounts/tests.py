from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework.test import APIClient
from rest_framework import status
from rest_framework.authtoken.models import Token

REGISTER_URL = reverse('accounts:register')
LOGIN_URL = reverse('accounts:login')
LOGOUT_URL = reverse('accounts:logout')
USER_UPDATE_URL = reverse('accounts:user-update')
PASSWORD_CHANGE_URL = reverse('accounts:password-change')
USERS_URL = reverse('accounts:users')


def create_user(**params):
    """Helper function to create new user"""
    return get_user_model().objects.create_user(**params)


class PublicUserApiTests(TestCase):
    """Test the users API (public)"""

    def setUp(self):
        self.client = APIClient()

    def test_create_valid_user_success(self):
        """Test creating using with a valid payload is successful"""
        payload = {
            'email': 'test@londonappdev.com',
            'password': 'testpass1',
            'username': 'name'
        }
        res = self.client.post(REGISTER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(username='name')
        token = Token.objects.get(user=user)
        self.assertTrue(user.check_password(payload['password']))
        self.assertEqual({'success': 'create user.'}, res.data)
        self.assertEqual(token.key, user.auth_token.key)

    def test_user_exists(self):
        """Test creating a user that already exists fails"""
        payload = {'email': 'test@londonappdev.com', 'password': 'testpass1', 'username': 'Test'}
        create_user(**payload)
        res = self.client.post(REGISTER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', res.data)

    def test_password_too_short(self):
        """Test that password must be more than 8 characters"""
        payload = {'email': 'test@londonappdev.com', 'password': 'pw', 'username': 'Test'}
        res = self.client.post(REGISTER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', res.data)
        user_exists = get_user_model().objects.filter(
            email=payload['email']
        ).exists()
        self.assertFalse(user_exists)

    def test_email_wrong(self):
        """Test that email must be valid"""
        payload = {'email': 'www.test.com', 'password': 'testpass1', 'username': 'Test'}
        res = self.client.post(REGISTER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', res.data)
        user_exists = get_user_model().objects.filter(
            username=payload['username']
        ).exists()
        self.assertFalse(user_exists)

    def test_create_token_for_user(self):
        """Test that a token is create for the user"""
        payload = {'email': 'test@londonappdev.com', 'password': 'testpass1', 'username': 'Test'}
        user = create_user(**payload)
        payload.pop('email')
        res = self.client.post(LOGIN_URL, payload)

        self.assertIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['token'], user.auth_token.key)

    def test_create_token_invalid_credentials(self):
        """Test that token is not create if invalid credentials are given"""
        payload = {'email': 'test@londonappdev.com', 'password': 'testpass1', 'username': 'Test'}
        create_user(**payload)
        payload = {'username': 'Test', 'password': 'wrong'}
        res = self.client.post(LOGIN_URL, payload)

        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_token_no_user(self):
        """Test that token is not created if user doesn't exist"""
        payload = {'username': 'Test', 'password': 'wrong'}
        res = self.client.post(LOGIN_URL, payload)

        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_token_missing_field(self):
        """Test that email and password are required"""
        res = self.client.post(LOGIN_URL, {'username': 'one', 'password': ''})

        self.assertNotIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_retrieve_users_unauthorized(self):
        """Test that authentication is required for USER_UPDATE_URL"""
        res = self.client.get(USER_UPDATE_URL)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_change_password_unauthorized(self):
        """Test that authentication is required for PASSWORD_CHANGE_URL"""
        res = self.client.post(PASSWORD_CHANGE_URL)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_unauthorized(self):
        """Test that authentication is required for LOGOUT_URL"""
        res = self.client.get(LOGOUT_URL)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateUserTests(TestCase):
    """Test API requests that require authentication"""

    def setUp(self):
        self.user = create_user(email='test@mohammad.com', password='testpass1', username='Name')
        self.token = Token.objects.create(user=self.user)

        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_retrieve_user_success(self):
        """Test retrieving user for logged in user"""
        res = self.client.get(USER_UPDATE_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)

        self.assertEqual(res.data, {
            'username': self.user.username,
            'email': self.user.email,
            'first_name': '',
            'last_name': '',
        })

    def test_post_update_user_not_allowed(self):
        """Test that POST is not allowed on the update url"""
        res = self.client.post(USER_UPDATE_URL, {})

        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_update_user_success(self):
        """Test updating the user for authenticated user"""
        payload = {'username': 'new_username', 'email': 'test_new@mohammad.com', 'first_name': 'first_name',
                   'last_name': 'last_name', }

        res = self.client.put(USER_UPDATE_URL, payload)
        print(res.data)
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, payload['username'])
        self.assertEqual(self.user.email, payload['email'])
        self.assertEqual(self.user.first_name, payload['first_name'])
        self.assertEqual(self.user.last_name, payload['last_name'])
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('success', res.data)

    def test_update_username_wrong(self):
        """test username must be unique"""
        payload = {'username': 'test2', 'email': 'test_new@mohammad.com', 'password': 'testpass2'}
        create_user(**payload)
        payload = {'username': 'test2', 'email': 'test_new@mohammad.com', 'first_name': 'first_name',
                   'last_name': 'last_name', }
        res = self.client.put(USER_UPDATE_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', res.data)

    def test_update_email_wrong(self):
        """test username must be unique"""
        payload = {'username': 'test2', 'email': 'test_new@mohammad.com', 'password': 'testpass2'}
        create_user(**payload)
        payload = {'username': 'test3', 'email': 'test_new@mohammad.com', 'first_name': 'first_name',
                   'last_name': 'last_name', }
        res = self.client.put(USER_UPDATE_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', res.data)

    def test_Change_password_success(self):
        """test changing password for authenticated user"""
        payload = {'new_password': 'testpass2', 'old_password': 'testpass1'}

        res = self.client.post(PASSWORD_CHANGE_URL, payload)

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(payload['new_password']))
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_logout_success(self):
        """test logouting for authenticated user"""
        res_logout = self.client.get(LOGOUT_URL)

        self.user.refresh_from_db()
        self.assertEqual(res_logout.status_code, status.HTTP_200_OK)
        token_count = Token.objects.count()
        self.assertEqual(token_count, 0)
