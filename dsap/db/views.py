import os
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from django.http import JsonResponse
from django.views import View
from .models import health


def handshake(request):
    if request.method == 'POST':
        # Receive client's public key
        client_public_key_pem = request.POST.get('public_key')

        if not client_public_key_pem:
            return JsonResponse({'error': "No public key received"}, status=400)

        # Load client's public key
        try:
            client_public_key = serialization.load_pem_public_key(
                client_public_key_pem.encode(),
                backend=default_backend()
            )
        except ValueError as e:
            return JsonResponse({'error': "Invalid public key format: {e}"}, status=400)

        try:
            # Generate AES key
            aes_key = os.urandom(32)  # Example: Using 256-bit key

            # Encrypt AES key with client's public RSA key
            encrypted_sha_key = client_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Simulate storing the AES key (should be securely managed in production)
            # For demonstration, you can store it in a session variable or database
            request.session['stored_aes_key'] = aes_key.hex()

            # Send the encrypted AES key back to the client
            return JsonResponse({'encrypted_aes_key': encrypted_sha_key.hex()}, status=200)
        except Exception as e:
            return JsonResponse({'error': f'Error during key exchange: {e}'}, status=500)

    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

# http methods: ["get", "post", "put", "patch", "delete", "head", "options", "trace"]


class healthView(View):
    def get(self, request, group, *args, **kwargs):
        # Retrieve data from the 'health' model
        if group == 'H':
            health_data_items = health.objects.all()
        elif group == 'R':
            # Exclude 'firstName' and 'lastName' for group R
            health_data_items = health.objects.values('id', 'gender', 'age', 'weight', 'height', 'healthHistory')
        else:
            return JsonResponse({'error': 'Invalid group'}, status=400)
        #---------------------------------------------------
        health_data = list(health_data_items.all().values()) #health_data_items=health.object

        # Calculate the hash of each row and append hash to the row
        for row in health_data:
            row_str = str(row).encode('utf-8')  # Convert to bytes for hashing
            row_hash = hashlib.sha256(row_str).hexdigest()
            row['hash'] = row_hash

        # Calculate the hash of concatenated row hashes
        concatenated_hashes = ''.join(row['hash'] for row in health_data)
        query_hash = hashlib.sha256(
            concatenated_hashes.encode('utf-8')).hexdigest()

        # Send the data along with the cumulative hash of row hashes as JSON response
        serialized_data = {
            "data": health_data,
            "query_hash": query_hash
        }
        return JsonResponse(serialized_data, safe=False)
    
    def post(self, request, group, *args, **kwargs):
        if request.method == 'POST':
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
            new_health_data_item = health(
                firstName=first_name,
                lastName=last_name,
                gender=gender,
                age=age,
                weight=weight,
                height=height,
                healthHistory=health_history
            )
            new_health_data_item.save()

            return JsonResponse({'message': 'Health data item added successfully'})
