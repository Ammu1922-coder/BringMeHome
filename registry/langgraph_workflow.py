# registry/langgraph_workflow.py
"""LangGraph workflow for matching IncidentReport to VulnerableIndividual.
Implements three nodes:
1. FilterGeoRadiusNode – selects missing individuals within 15‑mile radius.
2. AnalyzeMetadataNode – calls OpenAI GPT‑4o to compute confidence scores.
3. ConsolidateResultsNode – stores matches with confidence >= 75%.
The graph is intended to be triggered asynchronously via a Django signal.
"""
import os
import uuid
from typing import List, Dict, Any

import openai
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from asgiref.sync import sync_to_async

from langgraph.graph import Graph, START, END

from .models import IncidentReport, VulnerableIndividual, PotentialMatch

# Ensure OpenAI key is set
openai.api_key = getattr(settings, "OPENAI_API_KEY", os.getenv("OPENAI_API_KEY"))

# Helper to compute simple haversine distance (km) – placeholder using lat/long stored as "lat,lon" strings.
def _parse_coords(coord_str: str) -> tuple[float, float]:
    try:
        lat_str, lon_str = coord_str.split(',')
        return float(lat_str.strip()), float(lon_str.strip())
    except Exception:
        return 0.0, 0.0

def _haversine(lat1, lon1, lat2, lon2):
    from math import radians, cos, sin, asin, sqrt
    r = 6371.0  # Earth radius in km
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    return r * c

# ---- Nodes ----
async def filter_geo_radius_node(state: Dict) -> Dict:
    """Select missing VulnerableIndividuals within 15 miles (~24 km) of the report location."""
    report: IncidentReport = state["incident_report"]
    # Expect report.location_found to be a plain text address; for demo we assume lat,lon stored in description field as "lat,lon"
    # In real implementation you'd geocode the address. Here we mock with simple parse.
    report_lat, report_lon = _parse_coords(report.location_found)
    candidates: List[VulnerableIndividual] = []
    if report_lat == 0 and report_lon == 0:
        # fallback: return all missing
        qs = VulnerableIndividual.objects.filter(status="missing")
        candidates = await sync_to_async(list)(qs)
    else:
        all_missing = await sync_to_async(list)(VulnerableIndividual.objects.filter(status="missing"))
        for vi in all_missing:
            lat, lon = _parse_coords(vi.last_known_location)
            if lat == 0 and lon == 0:
                continue
            distance_km = _haversine(report_lat, report_lon, lat, lon)
            if distance_km <= 24.0:  # 15 miles ~ 24 km
                candidates.append(vi)
    state["candidates"] = candidates
    return state

async def analyze_metadata_node(state: Dict) -> Dict:
    """Use OpenAI to compare incident description with each candidate's data and assign confidence scores."""
    report: IncidentReport = state["incident_report"]
    candidates: List[VulnerableIndividual] = state.get("candidates", [])
    matches: List[Dict[str, Any]] = []
    for vi in candidates:
        prompt = (
            f"You are a compassionate matching assistant. Compare the following incident report description with the individual's profile and return a match confidence (0‑100).\n"
            f"Report description: {report.description}\n"
            f"Individual info: name={vi.full_name}, age={vi.age}, medical_notes={vi.medical_notes}, last_known_location={vi.last_known_location}\n"
            f"Respond ONLY with a number (e.g., 82)."
        )
        try:
            resp = await openai.ChatCompletion.acreate(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
            )
            content = resp.choices[0].message.content.strip()
            confidence = float(content)
        except Exception:
            confidence = 0.0
        matches.append({"vi": vi, "confidence": confidence})
    state["matches"] = matches
    return state

async def consolidate_results_node(state: Dict) -> Dict:
    """Create PotentialMatch entries for confident matches (>=75%)."""
    report: IncidentReport = state["incident_report"]
    matches: List[Dict[str, Any]] = state.get("matches", [])
    # Sort descending by confidence
    sorted_matches = sorted(matches, key=lambda m: m["confidence"], reverse=True)
    created = []
    async with sync_to_async(transaction.atomic)():
        for m in sorted_matches:
            if m["confidence"] >= 75.0:
                pm = PotentialMatch(
                    incident_report=report,
                    vulnerable_individual=m["vi"],
                    confidence=m["confidence"],
                )
                await sync_to_async(pm.save)()
                created.append(pm)
    state["potential_matches"] = created
    return state

# Build the graph
workflow = Graph()
workflow.add_node("filter_geo", filter_geo_radius_node)
workflow.add_node("analyze", analyze_metadata_node)
workflow.add_node("consolidate", consolidate_results_node)
workflow.add_edge(START, "filter_geo")
workflow.add_edge("filter_geo", "analyze")
workflow.add_edge("analyze", "consolidate")
workflow.add_edge("consolidate", END)

# Public entry point
async def run_match_workflow(incident_report_id: uuid.UUID):
    report = await sync_to_async(IncidentReport.objects.get)(id=incident_report_id)
    init_state = {"incident_report": report}
    await workflow.ainvoke(init_state)
