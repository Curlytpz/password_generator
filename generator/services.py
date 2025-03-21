import requests
import hashlib
import math
import random
import string

class PasswordService:
    @staticmethod
    def check_strength(password):
        if len(password) < 8:
            return "Weak"
        elif len(password) < 12:
            return "Medium"
        else:
            return "Strong"

    @staticmethod
    def check_common(password):
        common_passwords = ["password", "123456", "qwerty"]
        return password in common_passwords

    @staticmethod
    def check_repeated(password):
        for i in range(len(password) - 1):
            if password[i] == password[i + 1]:
                return True
        return False

    @staticmethod
    def calculate_entropy(password):
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += 32
        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        return entropy

    @staticmethod
    def check_leaked(password):
        sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)
        if response.status_code == 200:
            hashes = [line.split(":")[0] for line in response.text.splitlines()]
            return suffix in hashes
        else:
            raise Exception("Failed to check password leak.")

    @staticmethod
    def convert_weak_to_strong(password):
        if len(password) < 8:
            return password + "!@#123"
        return password

    @staticmethod
    def estimate_crack_time(password):
        entropy = PasswordService.calculate_entropy(password)
        guesses_per_second = 1e9  # Assume 1 billion guesses per second
        crack_time_seconds = (2 ** entropy) / guesses_per_second
        return f"{crack_time_seconds} seconds"

    @staticmethod
    def generate_passphrase(separator="-"):
        words = ["apple", "banana", "cherry", "delta", "echo", "foxtrot"]
        return separator.join(random.choices(words, k=3))

    @staticmethod
    def strength_report(password):
        return {
            "length": len(password),
            "has_uppercase": any(c.isupper() for c in password),
            "has_lowercase": any(c.islower() for c in password),
            "has_digits": any(c.isdigit() for c in password),
            "has_special": any(c in string.punctuation for c in password),
        }

    @staticmethod
    def password_recovery_reset(data):
        # Example implementation
        return {"message": "Password reset successful"}

    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def validate_hash(password, hash_value):
        return PasswordService.hash_password(password) == hash_value

    @staticmethod
    def encrypt_password(password):
        # Example implementation (reverse the password)
        return password[::-1]

    @staticmethod
    def check_reuse(password):
        # Example implementation
        return False  # Assume password is not reused