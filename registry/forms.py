from django import forms
from .models import VulnerableIndividual,IncidentReport

class VulnerableIndividualForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

    class Meta:
        model = VulnerableIndividual
        fields = [
            'full_name', 'age', 'photo', 'address',
            'emergency_contact_name', 'emergency_contact_phone',
            'medical_notes', 'last_known_location'
        ]
        widgets = {
            'full_name': forms.TextInput(attrs={
                'class': 'block w-full rounded-lg border-slate-300 shadow-sm focus:border-accent focus:ring-accent sm:text-sm p-3 border',
                'placeholder': 'Enter full name of the individual'
            }),
            'age': forms.NumberInput(attrs={
                'class': 'block w-full rounded-lg border-slate-300 shadow-sm focus:border-accent focus:ring-accent sm:text-sm p-3 border',
                'placeholder': 'Age (e.g. 72)'
            }),
            'photo': forms.ClearableFileInput(attrs={
                'class': 'block w-full text-sm text-slate-500 file:mr-4 file:py-2.5 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-accent/10 file:text-primary hover:file:bg-accent/25 transition-all cursor-pointer',
            }),
            'address': forms.Textarea(attrs={
                'class': 'block w-full rounded-lg border-slate-300 shadow-sm focus:border-accent focus:ring-accent sm:text-sm p-3 border h-20',
                'placeholder': 'Primary home address details...'
            }),
            'emergency_contact_name': forms.TextInput(attrs={
                'class': 'block w-full rounded-lg border-slate-300 shadow-sm focus:border-accent focus:ring-accent sm:text-sm p-3 border',
                'placeholder': 'e.g. Spouse, Son, Caretaker Name'
            }),
            'emergency_contact_phone': forms.TextInput(attrs={
                'class': 'block w-full rounded-lg border-slate-300 shadow-sm focus:border-accent focus:ring-accent sm:text-sm p-3 border',
                'placeholder': 'e.g. +1 555-0199'
            }),
            'medical_notes': forms.Textarea(attrs={
                'class': 'block w-full rounded-lg border-slate-300 shadow-sm focus:border-accent focus:ring-accent sm:text-sm p-3 border h-24',
                'placeholder': 'Critical medical conditions, dementia status, allergies, emergency actions, or medications...'
            }),
            'last_known_location': forms.Textarea(attrs={
                'class': 'block w-full rounded-lg border-slate-300 shadow-sm focus:border-accent focus:ring-accent sm:text-sm p-3 border h-24',
                'placeholder': 'Coordinates or description of where they frequently go'
            }),
        }

    def clean(self):
        cleaned_data = super().clean()
        if not self.user:
            return cleaned_data

        full_name = (cleaned_data.get('full_name') or '').strip().lower()
        address = (cleaned_data.get('address') or '').strip().lower()
        phone = (cleaned_data.get('emergency_contact_phone') or '').strip()

        if full_name and address and phone:
            duplicate_exists = VulnerableIndividual.objects.filter(
                creator=self.user,
                full_name__iexact=cleaned_data['full_name'].strip(),
                address__iexact=cleaned_data['address'].strip(),
                emergency_contact_phone=phone,
            ).exists()

            if duplicate_exists:
                raise forms.ValidationError(
                    "This same profile appears to already exist for your account. Please update the existing record instead of registering it again."
                )

        return cleaned_data

    def clean_emergency_contact_phone(self):
        phone = self.cleaned_data.get('emergency_contact_phone')
        # Basic validation to ensure digits or standard phone chars
        stripped = ''.join(c for c in phone if c.isdigit() or c in ['+', '-', ' '])
        if len(stripped) < 7:
            raise forms.ValidationError("Please enter a valid emergency telephone number (minimum 7 digits).")
        return phone

from django import forms

class IncidentReportForm(forms.Form):
    # Only keeping Name and Phone as requested
    citizen_name = forms.CharField(max_length=255, required=True, widget=forms.TextInput(attrs={
        'class': 'block w-full rounded-lg border-slate-300 shadow-sm focus:border-hope focus:ring-hope sm:text-sm p-3 border',
        'placeholder': 'Your Name'
    }))
    
    citizen_phone = forms.CharField(max_length=20, required=True, widget=forms.TextInput(attrs={
        'class': 'block w-full rounded-lg border-slate-300 shadow-sm focus:border-hope focus:ring-hope sm:text-sm p-3 border',
        'placeholder': 'Your Phone Number'
    }))

    # Keeping these as hidden fields so they can still capture the GPS
    latitude = forms.DecimalField(widget=forms.HiddenInput(), required=False)
    longitude = forms.DecimalField(widget=forms.HiddenInput(), required=False)