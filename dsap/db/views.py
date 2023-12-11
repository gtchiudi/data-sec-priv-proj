import hashlib
import hmac
import json
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.http import JsonResponse
from django.conf import settings
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework import status
from .models import Health, User
from .serializers import LoginSerializer
from .utils import decrypt_bool, decrypt_int, encrypt_aes


def handshake(request):
    # Only POST method is allowed
    if request.method == 'POST':
        # Receive client's public key
        client_public_key_pem = request.POST.get('public_key')

        if not client_public_key_pem:
            return JsonResponse({'error': "No public key received"}, status=400)

        # Load client's public RSA key
        try:
            client_public_key = serialization.load_pem_public_key(
                client_public_key_pem.encode(),
                backend=default_backend()
            )
        except ValueError as e:
            return JsonResponse({'error': "Invalid public key format: {e}"}, status=400)

        try:
            # Encrypt AES key with client's public RSA key
            encrypted_sha_key = client_public_key.encrypt(
                settings.AES_KEY,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Send the encrypted AES key back to the client
            return JsonResponse({'encrypted_aes_key': encrypted_sha_key.hex()}, status=200)
        except Exception as e:
            return JsonResponse({'error': f'Error during key exchange: {e}'}, status=500)

    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


class LoginView(APIView):
    def post(self, request):
        # Serialize the request login data
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            user = User.objects.filter(username=username).first()
            if not user:
                return Response({'error': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)
            # calculate the key using the users salt.
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                iterations=150000,
                salt=bytes.fromhex(user.salt),
                length=32,
            )
            hashed_password = kdf.derive(password.encode('utf-8')).hex()

            # Compare the hashed password key to the stored hashed password
            if hashed_password == user.password:
                # User is authenticated, generate or retrieve the token
                token, created = Token.objects.get_or_create(user=user)
                return Response({'token': token.key, 'message': 'Login successful'})
            else:
                return Response({'error': 'Invalid username or password'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class HealthView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        # Retrieve data from the 'Health' model
        group = request.user.group

        if group == 'H':
            # Fetch all fields for group 'H'
            health_data_items = Health.objects.all().values()
            health_data = list(health_data_items)
        elif group == 'R':
            # Exclude 'firstName' and 'lastName' for group 'R'
            health_data_items = Health.objects.all().values()
            health_data = list(health_data_items)
            for row in health_data:
                del row['firstName']
                del row['lastName']
        else:
            return JsonResponse({'error': 'Invalid group'}, status=400)

        # Perform decryption for specific fields
        for row in health_data:
            if 'encrypted_gender' in row:
                row['gender'] = decrypt_bool(row['encrypted_gender'])
                del row['encrypted_gender']
            if 'encrypted_age' in row:
                row['age'] = decrypt_int(row['encrypted_age'])
                del row['encrypted_age']

        # Create an HMAC key
        hmac_key = secrets.token_bytes(32)  # Generate a random key

        # Calculate the HMAC hash of each row
        for row in health_data:
            del row['id']  # Remove 'id' field from the row
            row_json = json.dumps(row, sort_keys=True).encode(
                'utf-8')  # Convert row to JSON
            row_hmac = hmac.new(hmac_key, row_json, hashlib.sha256).hexdigest()
            row['hash'] = row_hmac

        # Calculate the HMAC hash of concatenated row hashes
        concatenated_hashes = ''.join(row['hash'] for row in health_data)
        query_hmac = hmac.new(hmac_key, concatenated_hashes.encode(
            'utf-8'), hashlib.sha256).hexdigest()

        # Encrypt the HMAC key using settings.AES_KEY
        encrypted_hmac_key, iv = encrypt_aes(
            bytes.fromhex(settings.AES_KEY), hmac_key)

        # Prepare the serialized data with HMAC hash and encrypted key as JSON response
        serialized_data = {
            "data": health_data,
            "query_hash": query_hmac,
            "iv": iv.hex(),
            # Assuming encrypted_hmac_key is in bytes
            "encrypted_hmac_key": encrypted_hmac_key.hex()
        }
        return JsonResponse(serialized_data, safe=False)

    def post(self, request, *args, **kwargs):
        group = request.user.group
        # group besides H cannot access adding item
        if group != 'H':
            return JsonResponse({'error': 'Unauthorized access'}, status=403)

        # To extract data from the POST request
        first_name = request.POST.get('firstName')
        last_name = request.POST.get('lastName')
        gender = request.POST.get('gender')
        age = request.POST.get('age')
        weight = request.POST.get('weight')
        height = request.POST.get('height')
        health_history = request.POST.get('healthHistory')

        # Save new health data item
        new_health_data_item = Health(
            firstName=first_name,
            lastName=last_name,
            encrypted_gender=gender,
            encrypted_age=age,
            weight=weight,
            height=height,
            healthHistory=health_history
        )
        new_health_data_item.save()

        return JsonResponse({'message': 'Health data item added successfully'})
