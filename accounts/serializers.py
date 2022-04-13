from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from django.contrib.auth import get_user_model
import django.contrib.auth.password_validation as validators
from django.core import exceptions

User = get_user_model()


class UserRegisterSerializer(serializers.ModelSerializer):
    """Serializer for the users object"""

    class Meta:
        model = get_user_model()
        fields = ('email', 'password', 'username')

    def validate(self, data):
        # get the password from the data
        password = data.get('password')
        email = data.get('email')
        errors = dict()
        try:
            # validate the password,email and catch the exception
            validators.validate_password(password=password, user=User)
            user_exists = User.objects.get(email=email)
            if user_exists.is_active:
                errors['email'] = ['Duplicate email.']

        # the exception raised here is different than serializers.ValidationError
        except exceptions.ValidationError as e:
            errors['password'] = list(e.messages)
        except User.DoesNotExist:
            return super(UserRegisterSerializer, self).validate(data)

        if errors:
            raise serializers.ValidationError(errors)

    def create(self, validated_data):
        """Create a new user with encrypted password and return it"""
        return get_user_model().objects.create_user(**validated_data)


class UserUpdateSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email']

    def validate(self, data, ):
        email = data.get('email')
        errors = dict()
        try:
            # validate the email and catch the exception
            user_exists = User.objects.get(email=email)
            if user_exists.is_active and self.instance.email != email:
                errors['email'] = ['Duplicate email.']

        except User.DoesNotExist:
            pass
        if errors:
            raise serializers.ValidationError(errors)
        else:
            return super(UserUpdateSerializer, self).validate(data)


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128, required=True)
    new_password = serializers.CharField(max_length=128, required=True)

    def validate(self, data):
        password = data.get('new_password')
        errors = dict()
        try:
            # validate the password and catch the exception
            validators.validate_password(password=password, user=User)
            return super(PasswordChangeSerializer, self).validate(data)
        # the exception raised here is different than serializers.ValidationError
        except exceptions.ValidationError as e:
            errors['password'] = list(e.messages)

        if errors:
            raise serializers.ValidationError(errors)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email', 'is_active']
