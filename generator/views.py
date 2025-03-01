# api/views.py
import random
import string
from django.http import JsonResponse
from django.views import View

class PasswordGenerator(View):
    def get(self, request, method):
        if method == 'random':
            password = self.generate_random_password()
        elif method == 'custom':
            length = int(request.GET.get('length', 12))
            characters = request.GET.get('characters', string.ascii_letters + string.digits + string.punctuation)
            password = self.generate_custom_password(length, characters)
        elif method == 'easy':
            password = self.generate_easy_password()
        elif method == 'exclude-similar':
            password = self.generate_exclude_similar_password()
        elif method == 'expiration-reminder':
            return self.expiration_reminder()
        else:
            return JsonResponse({"error": "Invalid method"}, status=400)

        return JsonResponse({"password": password})

    def generate_random_password(self):
        length = 12
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    def generate_custom_password(self, length, characters):
        return ''.join(random.choice(characters) for _ in range(length))

    def generate_easy_password(self):
        words = ["apple", "banana", "cherry", "date", "elderberry"]
        return '-'.join(random.sample(words, 3))

    def generate_exclude_similar_password(self):
        characters = string.ascii_letters + string.digits.replace('0', '').replace('O', '')
        return ''.join(random.choice(characters) for _ in range(12))

    def expiration_reminder(self):
        # Here you can implement logic to check when the password was last changed
        # For now, we will return a static message
        return JsonResponse({"message": "It's time to change your password!"})