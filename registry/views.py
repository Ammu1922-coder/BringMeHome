from google import genai
from google.genai import types
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import VulnerableIndividual, IncidentReport
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
    if request.method == "POST":
        form = IncidentReportForm(request.POST, request.FILES)
        if form.is_valid():
            found_condition_flag = (request.POST.get('found_condition_flag') or '').strip().lower()
            base_description = form.cleaned_data['description']
            if found_condition_flag == 'yes':
                base_description = (base_description or '').strip() + "\n\n[Safety Alert] Appears injured / needs immediate medical help.".strip()

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
            messages.success(request, "Thank you for reporting. Your information has been received.")
            return redirect('incident_success')
    else:
        form = IncidentReportForm()

    api_key = getattr(settings, "GOOGLE_MAPS_API_KEY", "")
    return render(request, "registry/incident_report_found.html", {"form": form, "GOOGLE_MAPS_API_KEY": api_key, "report_type": "found"})


def incident_success(request):
    return render(request, "registry/incident_success.html")

@login_required
def family_dashboard(request):
    profiles = VulnerableIndividual.objects.filter(creator=request.user).distinct() if request.user.is_authenticated else []
    context = {
        "profiles": list(profiles),
    }
    return render(request, "registry/dashboard.html", context)


def _fallback_reply(question, language):
    q = (question or '').lower()
    if 'register' in q:
        base = 'You can register a missing or vulnerable person by opening the form, adding their details, and uploading a photo if available.'
    elif 'how does this website work' in q or 'how it works' in q:
        base = 'This website helps families report missing people, compare alerts, and view quick safety information for loved ones.'
    else:
        base = 'This assistant helps families understand the website and the steps to register or track a loved one safely.'

    translations = {
        'English': base,
        'Hindi': 'यह वेबसाइट परिवारों को गायब लोगों की रिपोर्ट करने, चेतावनियों की तुलना करने और अपने प्रियजनों के लिए जल्दी सुरक्षा जानकारी देखने में मदद करती है।',
        'Telugu': 'ఈ వెబ్సైట్ కుటుంబాలు క్షీణిస్తున్న లేదా లేని వ్యక్తులను నమోదు చేయడానికి, హెచ్చరికలను పోల్చి చూడడానికి మరియు సురక్షిత సమాచారాన్ని చూడటానికి సహాయపడుతుంది.',
        'Tamil': 'இந்த வலைதளம் குடும்பத்தினர் காணாமல் போன நபர்களைப் புகாரளிக்கவும், எச்சரிக்கைகளை ஒப்பிடவும், அன்புக்குரியவர்களுக்கான பாதுகாப்புத் தகவல்களை விரைவாகப் பார்க்கவும் உதவுகிறது.',
    }
    return translations.get(language, base)


@csrf_exempt
@login_required
def gemini_chat(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        data = json.loads(request.body)
        question = data.get("question", "")
        language = data.get("language", "English")

        if not question:
            return JsonResponse({"error": "Empty question"}, status=400)

        if settings.GEMINI_API_KEY:
            try:
                prompt = f"Explain this to an illiterate user in very simple {language}: {question}"
                response = client.models.generate_content(
                    model='gemini-2.5-flash',
                    contents=prompt,
                )
                reply = response.text or _fallback_reply(question, language)
                return JsonResponse({"reply": reply})
            except Exception:
                pass

        return JsonResponse({"reply": _fallback_reply(question, language)})
    except Exception as exc:
        return JsonResponse({"reply": f"I could not process that request right now. Please try again. ({exc})"})
@login_required
def found_alerts(request):
    """Match Center.

    Compare each registered profile against recent sightings using Gemini when available,
    and fall back to a simple text-based heuristic when the API key is not configured.
    """
    family_profiles = VulnerableIndividual.objects.filter(status__in=['missing', 'Missing', 'active', 'Active'])
    
    # FIX: Removed reporter__isnull=False so locally uploaded guest/test reports are included
    recent_reports = IncidentReport.objects.filter(
        report_type='found'
    ).order_by('-timestamp')[:10]

    # TERMINAL DEBUG PRINT STATEMENTS
    print("\n" + "="*40)
    print("--- DEBUG MATCH SYSTEM ACTIVE ---")
    print(f"Missing profiles found in DB: {family_profiles.count()}")
    print(f"Sighting reports found in DB: {recent_reports.count()}")
    print("="*40 + "\n")

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
            image_field.file.seek(0)  # Reset stream read pointer
            return image_field.file.read()
        except Exception as e:
            print(f"[IMAGE ERROR] Failed to read image file stream: {e}")
            return None

    if settings.GEMINI_API_KEY:
        prompt = (
            'Compare these two images. Are they the same person? '
            'Provide a similarity score from 0 to 100 and a brief reason why.'
        )

        for profile in family_profiles:
            profile_bytes = read_image_as_bytes(profile.photo)
            if not profile_bytes:
                print(f"[MATCH SKIP] Profile '{profile.full_name}' has no photo.")
                continue

            for report in recent_reports:
                report_bytes = read_image_as_bytes(report.uploaded_image)
                if not report_bytes:
                    print(f"[MATCH SKIP] Sighting report ID {report.id} has no image.")
                    continue

                try:
                    print(f"[API CALL] Sending conversion task to Gemini for Profile: {profile.full_name} vs Sighting ID: {report.id}...")
                    
                    # FIX: Wrap image byte parameters into valid types.Part objects required by google-genai schema validation
                    response = client.models.generate_content(
                        model='gemini-2.5-flash',
                        contents=[
                            prompt,
                            types.Part.from_bytes(
                                data=profile_bytes,
                                mime_type='image/jpeg',
                            ),
                            types.Part.from_bytes(
                                data=report_bytes,
                                mime_type='image/jpeg',
                            ),
                        ]
                    )

                    text = response.text or str(response)
                    score_match = re.search(r'(100|[1-9]?\d)\s*%?', text)
                    score = float(score_match.group(1)) if score_match else 0.0
                    print(f"[API SUCCESS] Gemini response score: {score}%")

                    key = (str(profile.id), str(report.id))
                    if key in seen or score < 10:
                        continue
                    seen.add(key)
                    matches.append({
                        'profile': profile,
                        'report': report,
                        'confidence': score,
                        'reason': text,
                    })
                except Exception as api_err:
                    print(f"[API CRASH] Live call execution failed: {api_err}")
                    traceback.print_exc()
                    continue
    else:
        print("[WARNING] settings.GEMINI_API_KEY was empty! Running text heuristic fallback loops.")
        for profile in family_profiles:
            for report in recent_reports:
                score = simple_text_score(profile, report)
                key = (str(profile.id), str(report.id))
                if key in seen or score < 10:
                    continue
                seen.add(key)
                matches.append({
                    'profile': profile,
                    'report': report,
                    'confidence': score,
                    'reason': 'Possible text-based match based on shared name, location, or description details.',
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

    from django.db import transaction
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
    
# @login_required
# def found_alerts(request):
#     """Match Center.

#     Compare each registered profile against recent sightings using Gemini when available,
#     and fall back to a simple text-based heuristic when the API key is not configured.
#     """
#     family_profiles = VulnerableIndividual.objects.filter(status__in=['missing', 'Missing', 'active', 'Active'])
    
#     # FIX: Removed reporter__isnull=False so locally uploaded guest/test reports are included
#     recent_reports = IncidentReport.objects.filter(
#         report_type='found'
#     ).order_by('-timestamp')[:10]

#     # TERMINAL DEBUG PRINT STATEMENTS
#     print("\n" + "="*40)
#     print("--- DEBUG MATCH SYSTEM ACTIVE ---")
#     print(f"Missing profiles found in DB: {family_profiles.count()}")
#     print(f"Sighting reports found in DB: {recent_reports.count()}")
#     print("="*40 + "\n")

#     def simple_text_score(profile, report):
#         profile_text = ' '.join([
#             (profile.full_name or '').lower(),
#             (profile.address or '').lower(),
#             (profile.medical_notes or '').lower(),
#             (profile.last_known_location or '').lower(),
#         ])
#         report_text = ' '.join([
#             (report.description or '').lower(),
#             (report.location_found or '').lower(),
#         ])
#         profile_words = set(w for w in profile_text.split() if len(w) > 3)
#         report_words = set(w for w in report_text.split() if len(w) > 3)
#         overlap = len(profile_words & report_words)
#         total = max(len(profile_words), len(report_words), 1)
#         return min(95.0, round((overlap / total) * 100.0, 1))

#     matches = []
#     seen = set()

#     def read_image_as_bytes(image_field):
#         if not image_field:
#             return None
#         try:
#             image_field.file.seek(0)  # Reset stream read pointer
#             return image_field.file.read()
#         except Exception as e:
#             print(f"[IMAGE ERROR] Failed to read image file stream: {e}")
#             return None

#     if settings.GEMINI_API_KEY:
#         prompt = (
#             'Compare these two images. Are they the same person? '
#             'Provide a similarity score from 0 to 100 and a brief reason why.'
#         )

#         for profile in family_profiles:
#             profile_bytes = read_image_as_bytes(profile.photo)
#             if not profile_bytes:
#                 print(f"[MATCH SKIP] Profile '{profile.full_name}' has no photo.")
#                 continue

#             for report in recent_reports:
#                 report_bytes = read_image_as_bytes(report.uploaded_image)
#                 if not report_bytes:
#                     print(f"[MATCH SKIP] Sighting report ID {report.id} has no image.")
#                     continue

#                 try:
#                     print(f"[API CALL] Sending conversion task to Gemini for Profile: {profile.full_name} vs Sighting ID: {report.id}...")
#                     response = client.models.generate_content(
#                         model='gemini-2.5-flash',
#                         contents=[
#                             prompt,
#                             {"mime_type": "image/jpeg", "data": profile_bytes},
#                             {"mime_type": "image/jpeg", "data": report_bytes},
#                         ]
#                     )

#                     text = response.text or str(response)
#                     score_match = re.search(r'(100|[1-9]?\d)\s*%?', text)
#                     score = float(score_match.group(1)) if score_match else 0.0
#                     print(f"[API SUCCESS] Gemini response score: {score}%")

#                     key = (str(profile.id), str(report.id))
#                     if key in seen or score < 10:
#                         continue
#                     seen.add(key)
#                     matches.append({
#                         'profile': profile,
#                         'report': report,
#                         'confidence': score,
#                         'reason': text,
#                     })
#                 except Exception as api_err:
#                     print(f"[API CRASH] Live call execution failed: {api_err}")
#                     traceback.print_exc()
#                     continue
#     else:
#         print("[WARNING] settings.GEMINI_API_KEY was empty! Running text heuristic fallback loops.")
#         for profile in family_profiles:
#             for report in recent_reports:
#                 score = simple_text_score(profile, report)
#                 key = (str(profile.id), str(report.id))
#                 if key in seen or score < 10:
#                     continue
#                 seen.add(key)
#                 matches.append({
#                     'profile': profile,
#                     'report': report,
#                     'confidence': score,
#                     'reason': 'Possible text-based match based on shared name, location, or description details.',
#                 })

#     matches = sorted(matches, key=lambda m: m.get('confidence', 0), reverse=True)

#     deduped = []
#     seen_profiles = set()
#     for m in matches:
#         pid = getattr(m.get('profile'), 'id', None)
#         if pid is None or pid in seen_profiles:
#             continue
#         seen_profiles.add(pid)
#         deduped.append(m)

#     from django.db import transaction
#     with transaction.atomic():
#         for m in deduped:
#             profile = m.get('profile')
#             if not profile:
#                 continue
#             current = str(getattr(profile, 'status', '')).lower()
#             if current in {'missing', 'active'}:
#                 profile.status = 'Found'
#                 profile.save(update_fields=['status'])

#     context = {'matches': deduped}
#     return render(request, 'registry/found_alerts.html', context)


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
    messages.warning(request, f"CRITICAL: {individual.full_name} has been reported missing! Active emergency broadcast initiated.")
    return redirect('family_dashboard')


@login_required
def report_safe(request, uuid):
    if request.method != 'POST':
        return HttpResponseBadRequest('POST required')
    individual = get_object_or_404(VulnerableIndividual, id=uuid, creator=request.user)
    individual.status = 'Safe'
    individual.save()
    messages.success(request, f"Wonderful news! {individual.full_name} has been marked as found and safe.")
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

    def is_likely_placeholder_photo(file_field):
        try:
            name = (getattr(file_field, 'name', '') or '').lower()
            tokens = ['verifier', 'placeholder', 'download_', 'download.jpeg', 'download.jpg', 'img1', 'img2', 'test']
            return any(t in name for t in tokens)
        except Exception:
            return False

    if not individual.photo or is_likely_placeholder_photo(individual.photo):
        return render(request, 'registry/sighting_matches.html', {
            'individual': individual,
            'matches': [],
            'threshold': threshold,
        })

    found_reports = IncidentReport.objects.filter(
        reporter__isnull=False,
        report_type='found',
    ).order_by('-timestamp')[:25]

    def read_image_as_bytes(image_field):
        if not image_field:
            return None
        return image_field.file.read()

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
        prompt = (
            'Compare ONLY these two images. '
            'Return ONLY a single integer similarity score between 0 and 100. '
            'Example output: "92%".'
        )

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
                        {"mime_type": "image/jpeg", "data": profile_bytes},
                        {"mime_type": "image/jpeg", "data": report_bytes},
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