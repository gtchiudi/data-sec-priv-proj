from db.models import health
import random
import faker
import django
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dsap.settings')

django.setup()

fake = faker.Faker()

data = [
    {
        'firstName': fake.first_name(),
        'lastName': fake.last_name(),
        'gender': random.choice([True, False]),
        'age': random.randint(18, 100),
        'weight': round(random.uniform(50, 100), 2),
        'height': round(random.uniform(150, 190), 2),
        'healthHistory': fake.text(max_nb_chars=512),
    }
    for _ in range(100)
]

instances = [health(**item) for item in data]

health.objects.bulk_create(instances)
