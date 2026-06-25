import uuid
import qrcode
from io import BytesIO
from django.db import models
from django.conf import settings
from django.core.files import File

class VulnerableIndividual(models.Model):
    STATUS_CHOICES = (
        ('Safe', 'Safe'),
        ('active', 'Active'),
        ('missing', 'Missing'),
        ('found', 'Found'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    creator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='created_individuals',
        help_text="The user/family who registered this individual."
    )
    full_name = models.CharField(max_length=255)
    age = models.PositiveIntegerField()
    photo = models.ImageField(
        upload_to='vulnerable_photos/',
        help_text="Recent photograph of the individual."
    )
    address = models.TextField(help_text="Primary residential address.")
    emergency_contact_name = models.CharField(max_length=255)
    emergency_contact_phone = models.CharField(max_length=20)
    medical_notes = models.TextField(
        blank=True,
        help_text="Crucial medical conditions, allergies, or instructions."
    )
    last_known_location = models.TextField(
        blank=True,
        help_text="Last known location coordinates or descriptive address."
    )
    qr_code_image = models.ImageField(
        upload_to='qr_codes/',
        blank=True,
        null=True,
        help_text="Automatically generated QR code for field identification."
    )
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='Safe'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Generate QR code automatically if it doesn't exist yet
        if not self.qr_code_image:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            # Encode the secure public scan link
            qr_data = f"http://localhost:8000/registry/scan/{self.id}/"
            qr.add_data(qr_data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="#1E3A5F", back_color="white")  # Brand primary blue!
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            
            filename = f"qr_{self.id}.png"
            self.qr_code_image.save(filename, File(buffer), save=False)

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.full_name} ({self.get_status_display()})"


class IncidentReport(models.Model):
    REPORT_TYPE_CHOICES = (
        ('missing', 'Missing'),
        ('found', 'Found'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='submitted_reports',
        help_text="The citizen reporter. Leave blank for anonymous reporting."
    )
    report_type = models.CharField(
        max_length=10,
        choices=REPORT_TYPE_CHOICES,
        default='missing',
        help_text="Whether this report is for a missing person or a found person."
    )
    uploaded_image = models.ImageField(
        upload_to='incident_photos/',
        help_text="Photo of the found individual or scene."
    )
    location_found = models.TextField(help_text="Address or description of where they were found.")
    latitude = models.DecimalField(max_digits=9, decimal_places=6, help_text="Latitude from map picker", null=True, blank=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, help_text="Longitude from map picker", null=True, blank=True)
    description = models.TextField(help_text="Details about the individual's appearance, behavior, or condition.")
    timestamp = models.DateTimeField(auto_now_add=True)
    audio_transcript = models.TextField(
        blank=True,
        null=True,
        help_text="Optional audio note transcription if a voice report was submitted."
    )

    def __str__(self):
        reporter_name = self.reporter.username if self.reporter else "Anonymous"
        return f"Report {self.id[:8]} by {reporter_name} at {self.timestamp.strftime('%Y-%m-%d %H:%M')}"
class PotentialMatch(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    incident_report = models.ForeignKey(
        IncidentReport,
        on_delete=models.CASCADE,
        related_name='potential_matches',
        help_text="The incident report this potential match originates from."
    )
    vulnerable_individual = models.ForeignKey(
        VulnerableIndividual,
        on_delete=models.CASCADE,
        related_name='match_candidates',
        help_text="Potential missing individual that may correspond to the report."
    )
    confidence = models.FloatField(help_text="Match confidence score (0-100).")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Match {self.vulnerable_individual.full_name} ({self.confidence:.1f}%) for report {self.incident_report.id[:8]}"
