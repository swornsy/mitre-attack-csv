import json
import pandas as pd
from stix2 import parse
import re

BUNDLE_PATH = "enterprise-attack-19.1.json"
OUTPUT_CSV = "mitre_attack_multilabel.csv"

# -----------------------------
# Utility functions
# -----------------------------

def extract_external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None

def clean_list(x):
    return "|".join(sorted(set(x))) if x else ""

def detect_difficulty_score(text):
    if not text:
        return "unknown"
    t = text.lower()
    if "difficult" in t or "hard" in t or "challenging" in t:
        return "hard"
    if "requires" in t or "correlate" in t:
        return "moderate"
    if "monitor" in t or "log" in t:
        return "easy"
    return "moderate"

def privilege_factor(perms):
    if not perms:
        return 1
    perms = [p.lower() for p in perms]
    if any("system" in p or "root" in p for p in perms):
        return 3
    if any("admin" in p for p in perms):
        return 2
    return 1

def compute_stealth(log_surface, privilege_factor, detection_difficulty):
    # Base stealth: fewer logs = stealthier
    base = max(0, 10 - log_surface)

    # Privilege bonus
    base += privilege_factor

    # Detection difficulty modifier
    if detection_difficulty == "hard":
        base += 2
    elif detection_difficulty == "moderate":
        base += 1

    return min(base, 10)

# -----------------------------
# Load STIX bundle
# -----------------------------

with open(BUNDLE_PATH, "r", encoding="utf-8") as f:
    bundle = parse(json.load(f), allow_custom=True)

techniques = {}
groups = {}
software = {}
campaigns = {}
mitigations = {}
relationships = []

# -----------------------------
# Parse objects
# -----------------------------

for obj in bundle.objects:
    t = obj.get("type")

    if t == "attack-pattern":
        tid = extract_external_id(obj)
        if tid:
            techniques[obj.id] = {
                "id": tid,
                "name": obj.get("name"),
                "tactic": [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])],
                "platforms": obj.get("x_mitre_platforms", []),
                "permissions_required": obj.get("x_mitre_permissions_required", []),
                "effective_permissions": obj.get("x_mitre_effective_permissions", []),
                "system_requirements": obj.get("x_mitre_system_requirements", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "data_components": obj.get("x_mitre_data_components", []),
                "detection": obj.get("x_mitre_detection", ""),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                "parent": obj.get("x_mitre_parent_attack_pattern", None),
                "groups": [],
                "software": [],
                "campaigns": [],
                "mitigations": []
            }

    elif t == "intrusion-set":
        gid = extract_external_id(obj)
        if gid:
            groups[obj.id] = gid

    elif t == "malware" or t == "tool":
        sid = extract_external_id(obj)
        if sid:
            software[obj.id] = sid

    elif t == "campaign":
        cid = extract_external_id(obj)
        if cid:
            campaigns[obj.id] = cid

    elif t == "course-of-action":
        mid = extract_external_id(obj)
        if mid:
            mitigations[obj.id] = mid

    elif t == "relationship":
        relationships.append(obj)

# -----------------------------
# Process relationships
# -----------------------------

for rel in relationships:
    src = rel.get("source_ref")
    tgt = rel.get("target_ref")
    rtype = rel.get("relationship_type")

    # Group uses Technique
    if rtype == "uses":
        if src in groups and tgt in techniques:
            techniques[tgt]["groups"].append(groups[src])
        if tgt in groups and src in techniques:
            techniques[src]["groups"].append(groups[tgt])

    # Software uses Technique
    if rtype == "uses":
        if src in software and tgt in techniques:
            techniques[tgt]["software"].append(software[src])
        if tgt in software and src in techniques:
            techniques[src]["software"].append(software[tgt])

    # Campaign uses Technique
    if rtype == "uses":
        if src in campaigns and tgt in techniques:
            techniques[tgt]["campaigns"].append(campaigns[src])
        if tgt in campaigns and src in techniques:
            techniques[src]["campaigns"].append(campaigns[tgt])

    # Mitigation mitigates Technique
    if rtype == "mitigates":
        if src in mitigations and tgt in techniques:
            techniques[tgt]["mitigations"].append(mitigations[src])
        if tgt in mitigations and src in techniques:
            techniques[src]["mitigations"].append(mitigations[tgt])

# -----------------------------
# Build CSV rows
# -----------------------------

rows = []

for tid, t in techniques.items():

    log_surface = len(t["data_components"])
    diff = detect_difficulty_score(t["detection"])
    priv_factor = privilege_factor(t["permissions_required"])
    stealth = compute_stealth(log_surface, priv_factor, diff)
    noise = 10 - stealth

    rows.append({
        "technique_id": t["id"],
        "technique_name": t["name"],
        "tactic": clean_list(t["tactic"]),
        "platforms": clean_list(t["platforms"]),
        "subtechniques": "",
        "parent_technique": t["parent"] or "",
        "groups": clean_list(t["groups"]),
        "software": clean_list(t["software"]),
        "campaigns": clean_list(t["campaigns"]),
        "data_sources": clean_list(t["data_sources"]),
        "data_components": clean_list(t["data_components"]),
        "mitigations": clean_list(t["mitigations"]),
        "detection_text": t["detection"],
        "system_requirements": clean_list(t["system_requirements"]),
        "permissions_required": clean_list(t["permissions_required"]),
        "effective_permissions": clean_list(t["effective_permissions"]),
        "stealth_score": stealth,
        "noise_score": noise,
        "log_surface_area": log_surface,
        "privilege_stealth_factor": priv_factor,
        "detection_difficulty": diff,
        "lolbin_usage": "",  # optional: fill with your own LOLBin mapping
        "edr_visibility": "",  # optional: derive from data sources
        "cloud_visibility": ""  # optional: derive from cloud platforms
    })

# -----------------------------
# Output CSV
# -----------------------------

df = pd.DataFrame(rows)
df.to_csv(OUTPUT_CSV, index=False)

print(f"Generated {OUTPUT_CSV} with {len(df)} techniques.")
