from django.urls import path

from . import views


urlpatterns = [
    path('safeguard/register/', views.safeguard_register_view, name='safeguard_register'),
    path('register-missing/', views.register_missing_person_view, name='register_missing_person'),
    path('profile/<uuid:uuid>/', views.profile_detail, name='profile_detail'),
    path('card/<uuid:uuid>/', views.digital_id_card, name='digital_id_card'),
    path('profile/poster/<uuid:uuid>/', views.generate_poster, name='generate_poster'),
    path('scan/<uuid:uuid>/', views.public_scan, name='public_scan'),
    path('report/missing/', views.incident_report_missing, name='incident_report_missing'),
    path('report/found/', views.incident_report_found, name='incident_report_found'),
    path('found_alerts/', views.found_alerts, name='found_alerts'),
    path('matches/<uuid:uuid>/', views.sighting_matches, name='sighting_matches'),
    path('reports/success/', views.incident_success, name='incident_success'),
    path('', views.family_dashboard, name='family_dashboard'),
    path('registry/', views.family_dashboard, name='registry_home'),
    path('report_found_person/', views.incident_report_found, name='report_found_person'),
    path('found_alerts/', views.found_alerts, name='found_alerts'),
    path('gemini-chat/', views.gemini_chat, name='gemini_chat'),
    #family actions
    path('profile/delete/<uuid:uuid>/', views.delete_profile, name='delete_profile'),
    path('profile/report-missing/<uuid:uuid>/', views.report_missing, name='report_missing'),
    path('profile/report-safe/<uuid:uuid>/', views.report_safe, name='report_safe'),
]




