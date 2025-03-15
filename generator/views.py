from rest_framework.decorators import api_view
from django.http import JsonResponse
from rest_framework.response import Response
from .serializers import PasswordSerializer
from .services import PasswordService
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import AllowAny
from rest_framework.decorators import permission_classes
from rest_framework_simplejwt.views import TokenObtainPairView
import random
import string
import hashlib


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


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def password_recovery_reset(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        try:
            result = PasswordService.password_recovery_reset(serializer.validated_data['password'])
            return Response({'message': result})
        except Exception as e:
            # Log the error for better understanding
            print(f"Error in password recovery reset: {str(e)}")
            return Response({'error': f'Internal server error: {str(e)}'}, status=500)
    return Response({'error': serializer.errors}, status=400)

@api_view(['POST'])
def check_strength(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        strength = PasswordService.check_strength(serializer.validated_data['password'])
        return Response({'strength': strength})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
def check_common(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        is_common = PasswordService.check_common(serializer.validated_data['password'])
        return Response({'is_common': is_common})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
def check_repeated(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        repeated_chars = PasswordService.check_repeated(serializer.validated_data['password'])
        return Response({'repeated_characters': repeated_chars})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
def calculate_entropy(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        entropy = PasswordService.calculate_entropy(serializer.validated_data['password'])
        return Response({'entropy': entropy})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
def check_leaked(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        is_leaked = PasswordService.check_leaked(serializer.validated_data['password'])
        return Response({'is_leaked': is_leaked})
    return Response({'error': serializer.errors}, status=400)


@api_view(['GET'])
def generate_random_password(request):
    length = validate_length(request.GET.get('length', 12))
    if length is None:
        return Response({'error': 'Invalid length parameter'}, status=400)
    
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choices(characters, k=length))
    return Response({'password': password})


@api_view(['POST'])
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
def generate_easy_password(request):
    words = ["apple", "banana", "cherry", "delta", "echo", "foxtrot", "golf", "hotel"]
    password = '-'.join(random.choices(words, k=3))
    return Response({'password': password})


@api_view(['GET'])
def generate_exclude_similar_password(request):
    length = validate_length(request.GET.get('length', 12))
    if length is None:
        return Response({'error': 'Invalid length parameter'}, status=400)
    
    characters = string.ascii_letters + string.digits + string.punctuation
    characters = characters.translate(str.maketrans('', '', 'O0Il'))
    password = ''.join(random.choices(characters, k=length))
    return Response({'password': password})


@api_view(['GET'])
def password_expiration_reminder(request):
    return Response({'message': "It's time to update your password for better security!"})


@api_view(['POST'])
def convert_weak_to_strong(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        strong_password = PasswordService.convert_weak_to_strong(serializer.validated_data['password'])
        return Response({'strong_password': strong_password})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
def estimate_crack_time(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        crack_time = PasswordService.estimate_crack_time(serializer.validated_data['password'])
        return Response({'crack_time': crack_time})
    return Response({'error': serializer.errors}, status=400)


@api_view(['GET'])
def generate_passphrase(request):
    passphrase = PasswordService.generate_passphrase()
    return Response({'passphrase': passphrase})


@api_view(['POST'])
def generate_passphrase_custom_separator(request):
    separator = request.data.get('separator', '-')
    passphrase = PasswordService.generate_passphrase(separator)
    return Response({'passphrase': passphrase})


@api_view(['POST'])
def strength_report(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        report = PasswordService.strength_report(serializer.validated_data['password'])
        return Response({'report': report})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
def password_hash(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        hashed_password = PasswordService.hash_password(serializer.validated_data['password'])
        return Response({'hashed_password': hashed_password})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
def validate_hash(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
       
        password = serializer.validated_data['password']
        hash_value = serializer.validated_data['hash']
        
      
        matches = PasswordService.validate_hash(password, hash_value)
        
        return Response({'matches': matches})
    
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
def encrypt_password(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        encrypted_password = PasswordService.encrypt_password(serializer.validated_data['password'])
        return Response({'encrypted_password': encrypted_password})
    return Response({'error': serializer.errors}, status=400)


@api_view(['POST'])
def check_reuse(request):
    serializer = PasswordSerializer(data=request.data)
    if serializer.is_valid():
        is_reused = PasswordService.check_reuse(serializer.validated_data['password'])
        return Response({'is_reused': is_reused})
    return Response({'error': serializer.errors}, status=400)

class PasswordService:
    @staticmethod
    def password_recovery_reset(password):
        if not password:
            raise ValueError("Password cannot be empty")
        # Additional logic for resetting the password
        return "Password reset successful"
    
class PasswordService:
    # Ensure this is properly indented with 4 spaces
    @staticmethod
    def validate_hash(password, hash_value):
        # Example: Use hashlib to compare the password with the hash
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        if hashed_password == hash_value:
            return True
        return False


def create_jwt_token(user):
    # The code inside this function should be indented properly.
    refresh = RefreshToken.for_user(user)
    
    # You can add custom claims to the refresh token here.
    refresh['role'] = user.role
    refresh['permissions'] = user.permissions
    
    return str(refresh.access_token)

def create_custom_token(user):
    # Generate refresh token for the user
    refresh = RefreshToken.for_user(user)

    # Add multiple custom claims to the payload to make it longer
    refresh.payload['custom_claim_1'] = 'value_for_claim_1'  # Claim 1
    refresh.payload['custom_claim_2'] = 'value_for_claim_2'  # Claim 2
    refresh.payload['custom_claim_3'] = 'value_for_claim_3'  # Claim 3
    refresh.payload['custom_claim_4'] = 'value_for_claim_4'  # Claim 4
    refresh.payload['custom_claim_5'] = 'value_for_claim_5'  # Claim 5
    refresh.payload['custom_claim_6'] = 'value_for_claim_6'  # Claim 6
    refresh.payload['custom_claim_7'] = 'value_for_claim_7'  # Claim 7
    refresh.payload['custom_claim_8'] = 'value_for_claim_8'  # Claim 8
    refresh.payload['custom_claim_9'] = 'value_for_claim_9'  # Claim 9
    refresh.payload['custom_claim_10'] = 'value_for_claim_10'  # Claim 10
    refresh.payload['custom_claim_11'] = 'value_for_claim_11'  # Claim 11
    refresh.payload['custom_claim_12'] = 'value_for_claim_12'  # Claim 12
    refresh.payload['custom_claim_13'] = 'value_for_claim_13'  # Claim 13
    refresh.payload['custom_claim_14'] = 'value_for_claim_14'  # Claim 14
    refresh.payload['custom_claim_15'] = 'value_for_claim_15'  # Claim 15
    refresh.payload['custom_claim_16'] = 'value_for_claim_16'  # Claim 16
    refresh.payload['custom_claim_17'] = 'value_for_claim_17'  # Claim 17
    refresh.payload['custom_claim_18'] = 'value_for_claim_18'  # Claim 18
    refresh.payload['custom_claim_19'] = 'value_for_claim_19'  # Claim 19
    refresh.payload['custom_claim_20'] = 'value_for_claim_20'  # Claim 20

    # Add enough custom claims to make the token larger than 80 words.
    refresh.payload['extra_info'] = 'This is additional information to make the token longer.'

    return str(refresh)
@permission_classes([AllowAny])  # Allows any user to access the endpoint
class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        # Perform the original functionality of getting tokens
        response = super().post(request, *args, **kwargs)

        # If authentication is successful, create a custom token
        if response.status_code == 200:
            user = User.objects.get(username=request.data.get('username'))
            custom_token = create_custom_token(user)

            # Add the custom token to the response
            response.data['custom_refresh_token'] = custom_token  # Add custom refresh token to the response

        return response