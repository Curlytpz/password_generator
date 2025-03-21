from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.http import JsonResponse
from rest_framework.response import Response
from .serializers import PasswordSerializer
from .services import PasswordService  # Corrected import
from django.contrib.auth import get_user_model  # Corrected import
from rest_framework.views import APIView
from rest_framework import status
import random
import string


def home(request):
    return JsonResponse({"message": "Welcome to the Password API!"})


def validate_length(value, default=12):
    try:
        length = int(value)
        if length <= 0:
            raise ValueError
        return length
    except ValueError:
        return None


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def check_strength(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        strength = PasswordService.check_strength(serializer.validated_data['password'])
        return Response({'strength': strength})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def check_common(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        is_common = PasswordService.check_common(serializer.validated_data['password'])
        return Response({'is_common': is_common})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def check_repeated(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        repeated_chars = PasswordService.check_repeated(serializer.validated_data['password'])
        return Response({'repeated_characters': repeated_chars})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def calculate_entropy(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        entropy = PasswordService.calculate_entropy(serializer.validated_data['password'])
        return Response({'entropy': entropy})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def check_leaked(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        try:
            is_leaked = PasswordService.check_leaked(serializer.validated_data['password'])
            return Response({'is_leaked': is_leaked})
        except Exception as e:
            print(f"Error checking password leak: {e}")
            return Response({'error': 'Failed to check password leak.'}, status=500)
    return Response({'error': serializer.errors}, status=400)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def generate_random_password(request):
    length = validate_length(request.GET.get('length', 12))
    if length is None:
        return Response({'error': 'Invalid length parameter'}, status=400)
    
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choices(characters, k=length))
    return Response({'password': password})


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def generate_custom_password(request):
    length = validate_length(request.data.get('length', 12))
    if length is None:
        return Response({'error': 'Invalid length parameter'}, status=400)
    
    include_upper = request.data.get('include_upper', True)
    include_digits = request.data.get('include_digits', True)
    include_special = request.data.get('include_special', True)
    
    characters = string.ascii_lowercase
    if include_upper:
        characters += string.ascii_uppercase
    if include_digits:
        characters += string.digits
    if include_special:
        characters += string.punctuation
    
    if not characters:
        return Response({'error': 'No character sets selected'}, status=400)
    
    password = ''.join(random.choices(characters, k=length))
    return Response({'password': password})


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def generate_easy_password(request):
    words = ["apple", "banana", "cherry", "delta", "echo", "foxtrot", "golf", "hotel"]
    password = '-'.join(random.choices(words, k=3))
    return Response({'password': password})


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def generate_exclude_similar_password(request):
    length = validate_length(request.GET.get('length', 12))
    if length is None:
        return Response({'error': 'Invalid length parameter'}, status=400)
    
    characters = string.ascii_letters + string.digits + string.punctuation
    characters = characters.translate(str.maketrans('', '', 'O0Il'))
    password = ''.join(random.choices(characters, k=length))
    return Response({'password': password})


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def password_expiration_reminder(request):
    return Response({'message': "It's time to update your password for better security!"})


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def convert_weak_to_strong(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        strong_password = PasswordService.convert_weak_to_strong(serializer.validated_data['password'])
        return Response({'strong_password': strong_password})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def estimate_crack_time(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        crack_time = PasswordService.estimate_crack_time(serializer.validated_data['password'])
        return Response({'crack_time': crack_time})
    return Response({'error': serializer.errors}, status=400)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def generate_passphrase(request):
    passphrase = PasswordService.generate_passphrase()
    return Response({'passphrase': passphrase})


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def generate_passphrase_custom_separator(request):
    separator = request.data.get('separator', '-')
    passphrase = PasswordService.generate_passphrase(separator)
    return Response({'passphrase': passphrase})


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def strength_report(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        report = PasswordService.strength_report(serializer.validated_data['password'])
        return Response({'report': report})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def password_recovery_reset(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        result = PasswordService.password_recovery_reset(serializer.validated_data)
        return Response(result)
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def password_hash(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        hashed_password = PasswordService.hash_password(serializer.validated_data['password'])
        return Response({'hashed_password': hashed_password})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def validate_hash(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        matches = PasswordService.validate_hash(serializer.validated_data['password'], serializer.validated_data['hash'])
        return Response({'matches': matches})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def encrypt_password(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        encrypted_password = PasswordService.encrypt_password(serializer.validated_data['password'])
        return Response({'encrypted_password': encrypted_password})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def check_reuse(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        is_reused = PasswordService.check_reuse(serializer.validated_data['password'])
        return Response({'is_reused': is_reused})
    return Response({'error': serializer.errors}, status=400)


User = get_user_model()

class UserRegistrationView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response(
                {"error": "Username and password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if User.objects.filter(username=username).exists():
            return Response(
                {"error": "Username already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = User.objects.create_user(username=username, password=password)
        return Response(
            {"message": "User created successfully.", "user_id": user.id},
            status=status.HTTP_201_CREATED
        )