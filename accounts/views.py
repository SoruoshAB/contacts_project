from rest_framework import status, generics
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.generics import ListAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.settings import api_settings

from .serializers import UserRegisterSerializer, UserUpdateSerializer, PasswordChangeSerializer, UserSerializer


class UserRegister(generics.GenericAPIView):
    """
        post:
        creat and register new user

        parameters: [email, username, password, first_name, last_name]
    """
    permission_classes = [AllowAny, ]
    serializer_class = UserRegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.POST)
        if serializer.is_valid():
            user = serializer.save()
            Token.objects.create(user=user)
            content = {'success': 'create user.'}
            return Response(content, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserUpdate(generics.GenericAPIView):
    """
    get:
        Retrieve and return authentication user

    put:
        Update the detail of a user instance

        parameters: [first_name, last_name, username, email]
    """

    permission_classes = [IsAuthenticated, ]
    serializer_class = UserUpdateSerializer

    def get(self, request):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        serializer = self.serializer_class(data=request.data, instance=request.user, partial=True)
        if serializer.is_valid():
            serializer.save()
            content = {'success': 'update account.'}
            return Response(content, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserPasswordChange(generics.GenericAPIView):
    """
    post:
        Send a new password to change  old password.

        parameters: [old_password, new_password]
    """
    permission_classes = [IsAuthenticated, ]
    serializer_class = PasswordChangeSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            new_password = serializer.data['new_password']
            old_password = serializer.data['old_password']

            if request.user.check_password(old_password):
                request.user.set_password(new_password)
                request.user.save()
                content = {'detail': 'update password.'}
                return Response(content, status=status.HTTP_200_OK)

            content = {'detail': 'your old password is not valid'}
            return Response(content, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Login(ObtainAuthToken):
    """
    post:
        Create a new auth token for the request.user

    parameters: [username, password]
    """
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES


class Logout(generics.GenericAPIView):
    """
    get:
        Remove all auth tokens owned by request.user.
    """
    permission_classes = [IsAuthenticated, ]

    def get(self, request):
        tokens = Token.objects.filter(user=request.user)
        for token in tokens:
            token.delete()
        content = {'success': 'User logged out.'}
        return Response(content, status=status.HTTP_200_OK)


class Users(ListAPIView):
    """
    get:
        Returns a list of all existing users.
    """
    permission_classes = [AllowAny, ]
    serializer_class = UserSerializer
    queryset = User.objects.all()
