from google import genai
from google.genai import types
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import admin,messages
from .models import VulnerableIndividual, IncidentReport, GeminMatchCache
from .forms import VulnerableIndividualForm, IncidentReportForm
import os
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponseBadRequest
import traceback
import base64
from django.db.models import Q
import json
import re
from django.conf import settings
from django.db import transaction


# Setup unified client globally using the correct setting name
client = genai.Client(api_key=settings.GEMINI_API_KEY)

@login_required
def register_missing_person_view(request):
    """Register a new vulnerable individual who is currently missing."""
    if request.method == 'POST':
        form = VulnerableIndividualForm(request.POST, request.FILES, user=request.user)
        if form.is_valid():
            individual = form.save(commit=False)
            individual.creator = request.user
            individual.status = 'missing'
            individual.save()
            messages.warning(request, f"CRITICAL ALERT: {individual.full_name} has been registered as missing! Active emergency search profile activated.")
            return redirect('family_dashboard')
        else:
            print("FORM ERRORS:", form.errors.as_data())
            messages.error(request, "Please correct the errors in the form below.")
    else:
        form = VulnerableIndividualForm(user=request.user)
    return render(request, 'registry/register_missing.html', {'form': form})


@login_required
def safeguard_register_view(request):
    if request.method == 'POST':
        form = VulnerableIndividualForm(request.POST, request.FILES, user=request.user)
        if form.is_valid():
            individual = form.save(commit=False)
            individual.creator = request.user
            individual.status = 'Safe'
            individual.save()
            messages.success(request, f"Successfully registered {individual.full_name} and generated a secure QR ID key!")
            return redirect('digital_id_card', uuid=individual.id)
        else:
            print("FORM ERRORS:", form.errors.as_data())
            messages.error(request, "Please correct the errors in the form below.")
    else:
        form = VulnerableIndividualForm(user=request.user)
    return render(request, 'registry/safeguard_register.html', {'form': form})

@login_required
def profile_detail(request, uuid):
    individual = get_object_or_404(VulnerableIndividual, id=uuid)
    return render(request, 'registry/detail.html', {'individual': individual})


@login_required
def digital_id_card(request, uuid):
    individual = get_object_or_404(VulnerableIndividual, id=uuid)
    return render(request, 'registry/id_card.html', {'individual': individual})


def public_scan(request, uuid):
    individual = get_object_or_404(VulnerableIndividual, id=uuid)
    first_name = individual.full_name.split()[0] if individual.full_name else "Individual"
    
    print("\n" + "!" * 50)
    print("[ALERT SYSTEM] BRINGMEHOME SCAN NOTIFICATION DETECTED!")
    print(f"Event: Scan event triggered for: {individual.full_name} (ID: {individual.id})")
    print(f"Email: Simulated Email sent to Caretaker ({individual.creator.username}): {individual.creator.email}")
    print(f"SMS: Simulated SMS sent to Caretaker Phone: {individual.emergency_contact_phone}")
    print(f"SMS Message: \"[BringMeHome Alert] Your loved one {first_name}'s QR ID card was scanned by a citizen. View safety page: http://localhost:8000/registry/scan/{individual.id}/\"")
    print("!" * 50 + "\n")
    
    return render(request, 'registry/scan.html', {
        'individual': individual,
        'first_name': first_name,
        'notification_simulated': True
    })


@login_required
def incident_report_missing(request):
    """Citizen incident reporting view for a missing person."""
    if not request.user.is_authenticated:
        return redirect('login')

    if getattr(request.user, 'role', None) not in (None, 'family'):
        return redirect('family_dashboard')

    if request.method == "POST":
        form = IncidentReportForm(request.POST, request.FILES)
        if form.is_valid():
            missing_severity = (request.POST.get('missing_severity') or '').strip().lower()
            base_description = form.cleaned_data['description']
            if missing_severity in {'high', 'medium', 'low'}:
                base_description = (base_description or '').strip() + f"\n\n[Urgency] Missing report severity: {missing_severity.capitalize()}.".strip()

            incident = IncidentReport(
                reporter=request.user,
                report_type='missing',
                uploaded_image=form.cleaned_data.get('image'),
                description=base_description,
                timestamp=form.cleaned_data['datetime'],
                latitude=form.cleaned_data.get('latitude'),
                longitude=form.cleaned_data.get('longitude'),
                location_found=form.cleaned_data.get('location_notes') or "",
            )
            incident.save()
            messages.success(request, "Thank you for reporting. Your information has been received.")
            return redirect('incident_success')
    else:
        form = IncidentReportForm()
    
    api_key = getattr(settings, "GOOGLE_MAPS_API_KEY", "")
    return render(request, "registry/incident_report_missing.html", {"form": form, "GOOGLE_MAPS_API_KEY": api_key, "report_type": "missing"})


@login_required
def incident_report_found(request):
    """Citizen incident reporting view for a found person."""
    if not request.user.is_authenticated:
        return redirect('login')

    if getattr(request.user, 'role', None) not in (None, 'family'):
        return redirect('family_dashboard')

    if request.method == "POST":
        form = IncidentReportForm(request.POST, request.FILES)
        if form.is_valid():
            base_description = (form.cleaned_data['description'] or '').strip()
            incident = IncidentReport(
                reporter=request.user,
                report_type='found',
                uploaded_image=form.cleaned_data.get('image'),
                description=base_description,
                timestamp=form.cleaned_data['datetime'],
                latitude=form.cleaned_data.get('latitude'),
                longitude=form.cleaned_data.get('longitude'),
                location_found=form.cleaned_data.get('location_notes') or "",
            )
            incident.save()
            messages.success(request, "Thank you for reporting this individual found. We will notify relevant authorities.")
            return redirect('incident_success')
    else:
        form = IncidentReportForm()
    
    api_key = getattr(settings, "GOOGLE_MAPS_API_KEY", "")
    return render(request, "registry/incident_report_found.html", {"form": form, "GOOGLE_MAPS_API_KEY": api_key, "report_type": "found"})
 

@login_required
def found_alerts(request):
    """Match Center.
    
    Compares missing individuals against recent sighting reports using local DB caching
    to prevent API rate limits, falling back gracefully to text heuristics.
    """
    family_profiles = VulnerableIndividual.objects.filter(
        status__in=['missing', 'Missing', 'active', 'Active', 'Found', 'found']
    )
    
    recent_reports = IncidentReport.objects.filter(
        report_type='found'
    ).order_by('-timestamp')[:10]

    def simple_text_score(profile, report):
        profile_text = ' '.join([
            (profile.full_name or '').lower(),
            (profile.address or '').lower(),
            (profile.medical_notes or '').lower(),
            (profile.last_known_location or '').lower(),
        ])
        report_text = ' '.join([
            (report.description or '').lower(),
            (report.location_found or '').lower(),
        
        ])
        profile_words = set(w for w in profile_text.split() if len(w) > 3)
        report_words = set(w for w in report_text.split() if len(w) > 3)
        overlap = len(profile_words & report_words)
        total = max(len(profile_words), len(report_words), 1)
        return min(95.0, round((overlap / total) * 100.0, 1))

    matches = []
    seen = set()

    def read_image_as_bytes(image_field):
        if not image_field:
            return None
        try:
            image_field.file.seek(0)
            return image_field.file.read()
        except Exception:
            return None

    for profile in family_profiles:
        for report in recent_reports:
            key = (str(profile.id), str(report.id))
            if key in seen:
                continue

            cached_match = GeminMatchCache.objects.filter(profile=profile, report=report).first()
            if cached_match:
                if cached_match.confidence >= 10.0:
                    seen.add(key)
                    matches.append({
                        'profile': profile,
                        'report': report,
                        'confidence': cached_match.confidence,
                        'reason': cached_match.reason or "Loaded from database cache.",
                    })
                continue

            if settings.GEMINI_API_KEY:
                profile_bytes = read_image_as_bytes(profile.photo)
                report_bytes = read_image_as_bytes(report.uploaded_image)

                if not profile_bytes or not report_bytes:
                    continue

                try:
                    prompt = 'Compare these two images. Are they the same person? Provide a similarity score from 0 to 100 and a brief reason why.'
                    response = client.models.generate_content(
                        model='gemini-2.5-flash',
                        contents=[
                            prompt,
                            types.Part.from_bytes(data=profile_bytes, mime_type='image/jpeg'),
                            types.Part.from_bytes(data=report_bytes, mime_type='image/jpeg'),
                        ]
                    )

                    text = response.text or str(response)
                    score_match = re.search(r'(100|[1-9]?\d)\s*%?', text)
                    score = float(score_match.group(1)) if score_match else 0.0

                    GeminMatchCache.objects.create(
                        profile=profile,
                        report=report,
                        confidence=score,
                        reason=text
                    )

                    if score >= 10.0:
                        seen.add(key)
                        matches.append({
                            'profile': profile,
                            'report': report,
                            'confidence': score,
                            'reason': text,
                        })

                except Exception:
                    score = simple_text_score(profile, report)
                    if score >= 10.0:
                        seen.add(key)
                        matches.append({
                            'profile': profile,
                            'report': report,
                            'confidence': score,
                            'reason': 'Fallback Match: API limit reached.',
                        })
            else:
                score = simple_text_score(profile, report)
                if score >= 10.0:
                    seen.add(key)
                    matches.append({
                        'profile': profile,
                        'report': report,
                        'confidence': score,
                        'reason': 'Possible text-based match.',
                    })

    matches = sorted(matches, key=lambda m: m.get('confidence', 0), reverse=True)
    deduped = []
    seen_profiles = set()
    for m in matches:
        pid = getattr(m.get('profile'), 'id', None)
        if pid is None or pid in seen_profiles:
            continue
        seen_profiles.add(pid)
        deduped.append(m)

    with transaction.atomic():
        for m in deduped:
            profile = m.get('profile')
            if not profile:
                continue
            current = str(getattr(profile, 'status', '')).lower()
            if current in {'missing', 'active'}:
                profile.status = 'Found'
                profile.save(update_fields=['status'])

    context = {'matches': deduped}
    return render(request, 'registry/found_alerts.html', context)


@login_required
def delete_profile(request, uuid):
    if request.method != 'POST':
        return HttpResponseBadRequest('POST required')
    individual = get_object_or_404(VulnerableIndividual, id=uuid, creator=request.user)
    individual.delete()
    messages.success(request, 'Profile deleted successfully.')
    return redirect('family_dashboard')


@login_required
def report_missing(request, uuid):
    if request.method != 'POST':
        return HttpResponseBadRequest('POST required')
    individual = get_object_or_404(VulnerableIndividual, id=uuid, creator=request.user)
    individual.status = 'missing'
    individual.save()
    messages.warning(request, f"CRITICAL: {individual.full_name} has been reported missing!")
    return redirect('family_dashboard')


@login_required
def report_safe(request, uuid):
    if request.method != 'POST':
        return HttpResponseBadRequest('POST required')
    individual = get_object_or_404(VulnerableIndividual, id=uuid, creator=request.user)
    individual.status = 'Safe'
    individual.save()
    messages.success(request, f"Wonderful news! {individual.full_name} has been marked safe.")
    return redirect('family_dashboard')


@login_required
def sighting_matches(request, uuid):
    threshold = 50
    individual = get_object_or_404(VulnerableIndividual, id=uuid, creator=request.user)

    if str(individual.status) not in ('missing', 'Missing', 'active', 'Active'):
        return render(request, 'registry/sighting_matches.html', {
            'individual': individual,
            'matches': [],
            'threshold': threshold,
        })

    found_reports = IncidentReport.objects.filter(
        report_type='found',
    ).order_by('-timestamp')[:25]

    def read_image_as_bytes(image_field):
        if not image_field:
            return None
        try:
            image_field.file.seek(0)
            return image_field.file.read()
        except Exception:
            return None

    profile_bytes = read_image_as_bytes(individual.photo)
    if not profile_bytes:
        return render(request, 'registry/sighting_matches.html', {
            'individual': individual,
            'matches': [],
            'threshold': threshold,
        })

    matches = []
    seen = set()

    if settings.GEMINI_API_KEY:
        prompt = 'Compare ONLY these two images. Return ONLY a similarity score between 0 and 100.'

        for report in found_reports:
            report_bytes = read_image_as_bytes(report.uploaded_image)
            if not report_bytes:
                continue

            key = (str(individual.id), str(report.id))
            if key in seen:
                continue
            seen.add(key)

            try:
                response = client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=[
                        prompt,
                        types.Part.from_bytes(data=profile_bytes, mime_type='image/jpeg'),
                        types.Part.from_bytes(data=report_bytes, mime_type='image/jpeg'),
                    ]
                )
                text = response.text or str(response)
                score_match = re.search(r'(100|[1-9]?\d)\s*%?', text)
                score = float(score_match.group(1)) if score_match else 0.0

                if score < threshold:
                    continue

                matches.append({
                    'profile': individual,
                    'report': report,
                    'confidence': score,
                    'reason': f"Gemini similarity score passed threshold ({threshold}%).",
                })
            except Exception:
                continue

    matches = sorted(matches, key=lambda m: m.get('confidence', 0), reverse=True)
    matches = matches[:1]

    return render(request, 'registry/sighting_matches.html', {
        'individual': individual,
        'matches': matches,
        'threshold': threshold,
    })


def incident_success(request):
    """Render a clean confirmation screen when a report is submitted successfully."""
    return render(request, 'registry/incident_success.html')


@login_required
def family_dashboard(request):
    """Render the central dashboard showcasing all tracked individuals."""
    # FIX: Uses your actual 'registry/dashboard.html' filename template routing string
    individuals = VulnerableIndividual.objects.filter(creator=request.user)
    return render(request, 'registry/dashboard.html', {'individuals': individuals})


@login_required
def gemini_chat(request):
    """Personal single-page chatbot interface powered by Gemini 2.5 Flash."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_message = data.get('message', '')
            if not user_message:
                return JsonResponse({'error': 'Message content cannot be empty.'}, status=400)
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=user_message,
            )
            return JsonResponse({'reply': response.text or "No response."})
        except Exception as chat_err:
            return JsonResponse({'error': str(chat_err)}, status=500)
    return render(request, 'registry/gemini_chat.html')
