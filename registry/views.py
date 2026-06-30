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

# def generate_poster(request, uuid):
#     individual = get_object_or_404(VulnerableIndividual, id=uuid)
#     return render(request, 'registry/poster.html', {'individual': individual})

def generate_poster(request, uuid):
    individual = get_object_or_404(VulnerableIndividual, id=uuid)

    print("========== POSTER ==========")
    print("ID:", individual.id)
    print("Name:", individual.full_name)
    print("Age:", individual.age)
    print("Address:", individual.address)
    print("Emergency Contact:", individual.emergency_contact_name)
    print("Phone:", individual.emergency_contact_phone)
    print("Medical Notes:", individual.medical_notes)
    print("Last Known:", individual.last_known_location)

    return render(request, "registry/poster.html", {
        "individual": individual
    })

def public_scan(request, uuid):
    individual = get_object_or_404(VulnerableIndividual, uuid=uuid)
    first_name = individual.full_name.split()[0] if individual.full_name else "Individual"
    
    current_domain = request.build_absolute_uri('/')
    
    print("\n" + "!" * 50)
    print("[ALERT SYSTEM] BRINGMEHOME SCAN NOTIFICATION DETECTED!")
    print(f"Event: Scan event triggered for: {individual.full_name} (UUID: {individual.uuid})")
    print(f"Email: Simulated Email sent to Caretaker ({individual.creator.username}): {individual.creator.email}")
    print(f"SMS: Simulated SMS sent to Caretaker Phone: {individual.emergency_contact_phone}")
    print("!" * 50 + "\n")
    
    # 🟢 REDIRECTS to your profile_detail page and passes the tracking flag '?action=scan_report'
    return redirect(f"{current_domain}profile/{individual.uuid}/?action=scan_report")

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
        creator=request.user,
        status__in=['missing', 'Missing', 'active', 'Active','Found','found','Resolved','resolved']
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

            # Check if the informant's phone number field exists on the report instance
            reporter_phone = report.reporter_phone if hasattr(report, 'reporter_phone') else None

            cached_match = GeminMatchCache.objects.filter(profile=profile, report=report).first()
            if cached_match:
                if cached_match.confidence >= 10.0:
                    seen.add(key)
                    matches.append({
                        'profile': profile,
                        'report': report,
                        'confidence': cached_match.confidence,
                        'reason': cached_match.reason or "Loaded from database cache.",
                        'reporter_phone': reporter_phone,  # Added to Cache Match
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
                            'reporter_phone': reporter_phone,  # Added to Gemini Match
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
                            'reporter_phone': reporter_phone,  # Added to Gemini Fallback
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
                        'reporter_phone': reporter_phone,  # Added to Text Match
                    })

    # Sort and remove duplicates from memory matching arrays
    matches = sorted(matches, key=lambda m: m.get('confidence', 0), reverse=True)
    deduped = []
    seen_profiles = set()
    for m in matches:
        pid = getattr(m.get('profile'), 'id', None)
        if pid is None or pid in seen_profiles:
            continue
        seen_profiles.add(pid)
        deduped.append(m)

    # Fixed: execution block wrapped in atomic context correctly from the outside
    with transaction.atomic():
        for m in deduped:
            profile = m.get('profile')
            report = m.get('report')
            confidence_score = m.get('confidence', 0)
            
            if not profile or not report:
                continue
            
            current_status = str(getattr(profile, 'status', '')).lower()
            
            # STAGE GATE 1: Only touch profiles that are actively missing
            if current_status in {'missing', 'active'}:
                
                # STAGE GATE 2: Only resolve if match is >= 50%
                if confidence_score >= 50.0:
                    profile.status = 'Found'
                    
                    # Update last_known_location with where they were found
                    if report.location_found:
                        profile.last_known_location = report.location_found
                    elif report.description:
                        # Fallback to description text if location notes are blank
                        profile.last_known_location = report.description[:100]
                    
                    profile.save(update_fields=['status', 'last_known_location'])
                else:
                    # If match score is below 50%, skip status modification safely
                    continue

    # Return the clean deduped collection context to your dashboard view templates
    return render(request, 'registry/found_alerts.html', {
        'deduped_matches': deduped,
        'matches':deduped,
    })


@login_required
def report_missing(request, uuid):
    if request.method != 'POST':
        return HttpResponseBadRequest('POST required')
    
    # SAFE LOOKUP: Replaces any risky [0] or direct indexes
    individual = get_object_or_404(VulnerableIndividual, id=uuid, creator=request.user)
    
    # 🟢 FIXED: Changed 'Missing' to 'missing' to match your registration system!
    individual.status = 'missing'
    individual.save(update_fields=['status'])  # Performance boost: only save the changed field
    
    messages.warning(request, f"CRITICAL: {individual.full_name} has been reported missing!")
    return redirect('family_dashboard')


@login_required
def report_safe(request, uuid):
    if request.method == 'POST':
        individual = get_object_or_404(VulnerableIndividual, id=uuid, creator=request.user)
        
    
    # SAFE LOOKUP: Replaces any risky [0] or direct indexes
    individual = get_object_or_404(VulnerableIndividual, id=uuid, creator=request.user)
    
    individual.status = 'found'
    individual.save()

    messages.success(request, f"Wonderful news! {individual.full_name} has been marked safe.")
    return redirect('family_dashboard')

@login_required
def sighting_matches(request, uuid):
    threshold = 50
    individual = get_object_or_404(VulnerableIndividual, id=uuid, creator=request.user)

    # If the individual isn't marked as missing, return empty lists immediately
    if str(individual.status) not in ('missing', 'Missing', 'active', 'Active', 'resolved', 'Resolved'):
        return render(request, 'registry/sighting_matches.html', {
            'individual': individual,
            'matches': [],
            'all_reports': [],
            'threshold': threshold,
        })

    # Pull the 25 most recent public 'found' reports to scan against
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
            'all_reports': [],
            'threshold': threshold,
        })

    high_matches = []
    all_processed_reports = []
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

                # Build the item payload dictionary
                match_item = {
                    'profile': individual,
                    'report': report,
                    'confidence': score,
                    'reason': f"Gemini similarity score evaluated at {score}%.",
                }

                # Save EVERYTHING to the all_reports list for the secondary timeline matrix
                all_processed_reports.append(match_item)

                # Save ONLY high confidence items to the primary highlights stack
                if score >= threshold:
                    high_matches.append(match_item)

            except Exception:
                continue

    # Sort high confidence matches from best to worst (No slicing so you see multiple matches!)
    high_matches = sorted(high_matches, key=lambda m: m.get('confidence', 0), reverse=True)
    
    # Sort the complete list by newest reports first
    all_processed_reports = sorted(all_processed_reports, key=lambda m: m['report'].timestamp, reverse=True)

    return render(request, 'registry/sighting_matches.html', {
        'individual': individual,
        'matches': high_matches,                 # Feeds top comparison panel
        'all_reports': all_processed_reports,    # Feeds bottom timeline matrix
        'threshold': threshold,
    })


def incident_success(request):
    """Render a clean confirmation screen when a report is submitted successfully."""
    return render(request, 'registry/incident_success.html')

@login_required
def delete_profile(request, uuid):
    """Safely delete a profile record."""
    # 🟢 If you are a staff/admin user, bypass the creator restriction
    if request.user.is_staff:
        profile = get_object_or_404(VulnerableIndividual, id=uuid)
    else:
        # Regular users can still only delete their own registered profiles
        profile = get_object_or_404(VulnerableIndividual, id=uuid, creator=request.user)
    
    # Perform the deletion
    profile.delete()
    
    messages.success(request, "The profile has been successfully permanently removed.")
    return redirect('family_dashboard')


@login_required
def family_dashboard(request):


    new_reports = IncidentReport.objects.filter(individual=person, is_viewed=False).order_by("-timestamp")

    secured_profiles = VulnerableIndividual.objects.filter(
        creator=request.user,
        status__in=['safe', 'Safe', 'safeguard', 'Safeguard', 'active', 'Active']
    )

    # 🚨 My Active Missing Reports
    active_missing = VulnerableIndividual.objects.filter(
        creator=request.user,
        status__in=['missing', 'Missing']
    )

    # ✅ My Resolved Cases
    resolved_cases = VulnerableIndividual.objects.filter(
        creator=request.user,
        status__in=['Found', 'found']
    )

    new_found_alerts = IncidentReport.objects.filter(
    individual__creator=request.user,
    report_type='found',
    is_viewed=False
    ).order_by('-timestamp')

    new_reports = IncidentReport.objects.filter(
    individual__creator=request.user,
    is_viewed=False
    )

    latest_scan = IncidentReport.objects.filter(
    individual__creator=request.user,
    report_type='found',
    is_viewed=False
    ).order_by('-timestamp').first()

    return render(request, 'registry/dashboard.html', {
        'person': person,
        'new_reports': new_reports,
        'secured_profiles': secured_profiles,
        'active_missing': active_missing,
        'resolved_cases': resolved_cases,
        'new_found_alerts': new_found_alerts,
        'latest_scan': latest_scan,
        "new_reports": new_reports,
    })

@login_required
@csrf_exempt # Ensures your frontend fetch request passes through without CSRF blockages
def gemini_chat(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests are allowed.'}, status=405)

    try:
        # 1. Safely parse the raw JSON data from the frontend fetch call
        data = json.loads(request.body)
        question = data.get('question', '').strip()
        language = data.get('language', 'English')
        
        if not question:
            return JsonResponse({'error': 'Message content cannot be empty.'}, status=400)
            
        # 2. Check for your Google AI Studio API key
        api_key = os.environ.get("GEMINI_API_KEY") or getattr(settings, "GEMINI_API_KEY", None)
        if not api_key:
            return JsonResponse({'error': 'API Key is missing or misconfigured.'}, status=500)

        # 3. Initialize the modern GenAI Client using your imported 'genai' module
        client = genai.Client(api_key=api_key)
        
        # Craft a contextual system instruction prompt to keep responses professional and localized
        prompt = (
            f"You are a helpful, empathetic assistant for a missing persons search registry application named BringMeHome. "
            f"Answer the user's question directly, clearly, and completely in {language}. "
            f"Question: {question}"
        )

        # 4. Generate the response text using the recommended 'gemini-1.5-flash' model
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        
        ai_reply = response.text if response.text else "I couldn't generate a clear response. Please try again."

        # 5. Return success pathway response to your chat panel bubble
        return JsonResponse({'reply': ai_reply})
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON format received.'}, status=400)
        
    except Exception as e:
        # 6. Fallback safety pathway: Prints the crash log inside your CMD terminal so it never returns None
        print("--- GEMINI CHAT ERROR TRACEBACK ---")
        traceback.print_exc()
        return JsonResponse({'error': f"Internal Server Error: {str(e)}"}, status=500)


@csrf_exempt  
def report_incident_auto(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)
        
    try:
        data = json.loads(request.body)
        individual_id = data.get('individual_id')
        lat = data.get('latitude')
        lng = data.get('longitude')
        
        # 1. Grab the missing individual from your DB
        # vulnerable_person = get_object_or_404(VulnerableIndividual, uud=individual_id)
        
        # 2. Create the automated checkpoint log
        print(f"📍 SUCCESS! Received QR Scan Tracking Ping: Lat {lat}, Lng {lng} for Individual ID {individual_id}")
        
        # Log it to your database here...
        
        return JsonResponse({'status': 'success', 'message': 'Location tracked'})
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def profile_detail(request, pk=None, **kwargs):
    # Determine the ID regardless of whether Django calls it 'pk' or 'uuid'
    profile_id = pk or kwargs.get('uuid')
    person = get_object_or_404(VulnerableIndividual, id=profile_id)
    action = request.GET.get('action')
    
    # 🕵️‍♂️ Case 1: Helpful citizen scanned the QR code
    if action == 'scan_report':
        # Initialize form here so it always exists
        form = IncidentReportForm(request.POST or None)
        
        if request.method == 'POST':
            if form.is_valid():
                # Manually create the object
                report = IncidentReport(
                    individual=person,
                    report_type='found',
                    location_found="Captured via QR scan GPS form",
                    description=(
                        f"🚨 DIRECT QR SCAN REPORT\n"
                        f"Reporter Name: {form.cleaned_data['citizen_name']}\n"
                        f"Reporter Phone: {form.cleaned_data['citizen_phone']}\n"
                    ),
                    latitude=form.cleaned_data.get('latitude'),
                    longitude=form.cleaned_data.get('longitude')
                )
                report.save()
                return render(request, 'registry/incident_success.html', {'person': person})
        
        # Render the scan page with the form
        return render(request, 'registry/public_scan_report.html', {'person': person, 'form': form})
        
    # 🏠 Case 2: Standard dashboard for the family/caretaker
    return render(request, 'registry/dashboard.html', {'person': person})


def view_report(request, report_id):
    report = get_object_or_404(IncidentReport, id=report_id)

    print("========== REPORT ==========")
    print("Report ID:", report.id)
    print("Individual:", report.individual)

    if report.individual:
        print("Individual ID:", report.individual.id)
        print("Name:", report.individual.full_name)
        print("Emergency Contact:", report.individual.emergency_contact_name)
        print("Phone:", report.individual.emergency_contact_phone)
        print("Address:", report.individual.address)

    report.is_viewed = True
    report.save()

    return render(request, "registry/detail.html", {"report": report, 'individual':report.individual,
    })

# def view_report(request, report_id):
#     report = get_object_or_404(IncidentReport, id=report_id)
    
#     # Add these print statements
#     print(f"--- DEBUGGING REPORT ---")
#     print(f"Individual: {report.individual}")
#     print(f"Name: {report.individual.full_name if report.individual else 'No Individual'}")
    
#     report.is_viewed = True
#     report.save()
    
#     return render(request, 'registry/detail.html', {'report': report})