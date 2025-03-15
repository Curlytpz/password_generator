import hashlib
import bcrypt
import random
import string
import time

class PasswordService:

    @staticmethod
    def check_strength(password):
        if len(password) < 6:
            return "Weak"
        elif len(password) < 10:
            return "Medium"
        return "Strong"

    @staticmethod
    def check_common(password):
        common_passwords = {"password", "123456", "qwerty", "abc123"}
        return password in common_passwords

    @staticmethod
    def check_repeated(password):
        return any(password[i] == password[i+1] for i in range(len(password)-1))

    @staticmethod
    def calculate_entropy(password):
        unique_chars = len(set(password))
        return len(password) * unique_chars

    @staticmethod
    def check_leaked(password):
        # Mock leak check (real implementation should query a database)
        leaked_passwords = {"password123", "admin", "letmein"}
        return password in leaked_passwords

    @staticmethod
    def convert_weak_to_strong(password):
        return password + "!@#" + str(random.randint(100, 999))

    @staticmethod
    def estimate_crack_time(password):
        complexity = len(set(password))
        return round(2 ** complexity / 1e6, 2)  # Mock formula for time in seconds

    @staticmethod
    def generate_passphrase(separator="-"):
        words = ["apple", "banana", "cherry", "delta", "echo", "foxtrot"]
        return separator.join(random.choices(words, k=4))

    @staticmethod
    def strength_report(password):
        return {
            "length": len(password),
            "has_numbers": any(char.isdigit() for char in password),
            "has_special": any(char in string.punctuation for char in password),
            "strength": PasswordService.check_strength(password),
        }

    @staticmethod
    def password_recovery_reset(data):
        username = data.get("username")
        new_password = data.get("password")
        if username and new_password:
            return {"message": "Password reset successful"}
        return {"error": "Invalid data"}

    @staticmethod
    def hash_password(password):
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode()

    @staticmethod
    def validate_hash(password, hashed):
        return bcrypt.checkpw(password.encode(), hashed.encode())

    @staticmethod
    def encrypt_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def check_reuse(password):
        old_passwords = {"oldpassword1", "mypassword", "securepass"}
        return password in old_passwords

