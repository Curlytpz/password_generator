from rest_framework import serializers

class PasswordSerializer(serializers.Serializer):
    password = serializers.CharField(required=True)
    hash = serializers.CharField(required=True)
