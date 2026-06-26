from django.contrib import admin
from .models import VulnerableIndividual, IncidentReport, GeminMatchCache

@admin.register(VulnerableIndividual)
class VulnerableIndividualAdmin(admin.ModelAdmin):
    # FIX: Changed 'name' to 'full_name' and removed 'location_notes'
    list_display = ('full_name', 'status', 'emergency_contact_phone', 'id')
    list_filter = ('status',)
    search_fields = ('full_name', 'medical_notes')

@admin.register(IncidentReport)
class IncidentReportAdmin(admin.ModelAdmin):
    # FIX: Changed 'location_notes' to 'location_found' to match your views.py structure
    list_display = ('id', 'report_type', 'location_found', 'timestamp', 'reporter')
    list_filter = ('report_type', 'timestamp')
    search_fields = ('description', 'location_found')

@admin.register(GeminMatchCache)
class GeminMatchCacheAdmin(admin.ModelAdmin):
    list_display = ('id', 'profile', 'report', 'confidence', 'created_at')