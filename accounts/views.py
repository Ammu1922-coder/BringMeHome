from django.shortcuts import redirect, render
from django.urls import reverse
from django.contrib.auth import login
from django.views.generic import FormView

from .forms import FamilySignUpForm


class FamilySignUpView(FormView):
    template_name = "registration/signup.html"
    form_class = FamilySignUpForm

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        # After signup, take user to the dashboard
        return redirect(reverse("family_dashboard"))

    def form_invalid(self, form):
        # Log validation errors so you can see why signup isn't saving
        # even if the template isn't showing them.
        print("[FamilySignUpView] form.errors:", form.errors)
        return super().form_invalid(form)



