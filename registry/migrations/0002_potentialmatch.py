from django.db import migrations, models
import uuid

class Migration(migrations.Migration):
    initial = False
    dependencies = [
        ('registry', '0001_initial'),  # adjust if your last migration name differs
    ]
    operations = [
        migrations.CreateModel(
            name='PotentialMatch',
            fields=[
                ('id', models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)),
                ('confidence', models.FloatField(help_text='Match confidence score (0-100).')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('incident_report', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='potential_matches', to='registry.IncidentReport', help_text='The incident report this potential match originates from.')),
                ('vulnerable_individual', models.ForeignKey(on_delete=models.deletion.CASCADE, related_name='match_candidates', to='registry.VulnerableIndividual', help_text='Potential missing individual that may correspond to the report.')),
            ],
        ),
    ]
