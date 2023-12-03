import os
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
    def get(self, request, *args, **kwargs):
        serialized_data = list(health.objects.all().values())
        return JsonResponse(serialized_data, safe=False)
