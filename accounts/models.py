from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    ROLE_CHOICES = (
        ('family', 'Family'),
        ('citizen', 'Citizen'),
        ('admin', 'Admin'),
    )
    
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='citizen',
        help_text="The role that defines the user's permissions and interface."
    )

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

    @property
    def is_family(self):
        return self.role == 'family'

    @property
    def is_citizen(self):
        return self.role == 'citizen'

    @property
    def is_admin(self):
        return self.role == 'admin' or self.is_superuser
