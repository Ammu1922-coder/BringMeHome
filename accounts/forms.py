from django import forms
from django.contrib.auth.forms import UserCreationForm

from .models import User


class FamilySignUpForm(UserCreationForm):
    """Creates a Django User for the family member (role='family')."""

    # Make sure we explicitly render password fields with PasswordInput
    # (UserCreationForm already does this, but we lock it in here)
    password1 = forms.CharField(widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")


    def clean_password1(self):
        password1 = self.cleaned_data.get("password1")
        if password1 and len(password1) < 6:
            raise forms.ValidationError("Password must be at least 6 characters.")
        return password1

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords do not match.")

        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.role = "family"
        if commit:
            user.save()
        return user


