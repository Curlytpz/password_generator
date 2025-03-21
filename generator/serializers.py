from rest_framework import serializers

class PasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=128)
    username = serializers.CharField(max_length=150, required=False)  # For password recovery
    hash = serializers.CharField(max_length=256, required=False)  # For validate_hash
    separator = serializers.CharField(max_length=1, required=False)  # For generate_passphrase_custom_separator