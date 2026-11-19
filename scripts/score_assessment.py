#!/usr/bin/env python3
"""score_assessment.py - score a Security & Crypto-Agility Maturity Assessment (stdlib only).

Input: JSON answers file (see ../examples/answers.sample.json).
  answers[]: {"id","domain":"D1".."D9","score":0-5,"basis":"evidence-seen"|"self-reported","gate"?:<gate key>,"text"?}
  d9_in_scope: bool (default: true if any D9 answers)
  data_sensitivity: low|medium|high ; data_shelf_life: "<3y"|"3-10y"|">10y"
Output: JSON matching ../schemas/assessment.schema.json.

Rules: domain score = mean(0-5) x 20. Verified caps self-reported answers at 3.
Bands: Exposed <40, Developing 40-59, Managed 60-79, Resilient 80+.
A critical gate (answer score <= 1 on a gate question) caps the band at Developing.
Heuristic self-assessment; not an audit or certification.
"""
import argparse, json, sys

DOMAINS = {
    "D1": ("Governance & people", 12), "D2": ("Asset & crypto inventory", 12), "D3": ("Identity & access", 14),
    "D4": ("Crypto-agility & post-quantum readiness", 12), "D5": ("Secure build, web & supply chain", 12),
    "D6": ("Detection & logging", 10), "D7": ("Incident response & NIS2 reporting", 10),
    "D8": ("Backup & continuity", 10), "D9": ("AI & agent security", 8),
}
GATES = {
    "mfa_admin_email": "No MFA on admin/email accounts",
    "backup_restore_tested": "Backups never restore-tested",
    "ir_plan": "No incident response plan",
    "public_tls_valid": "Public TLS invalid or expired",
    "asset_inventory": "No asset inventory",
}
BANDS = [(80, "Resilient"), (60, "Managed"), (40, "Developing"), (0, "Exposed")]
BAND_RANK = {"Exposed": 0, "Developing": 1, "Managed": 2, "Resilient": 3}


def band(score):
    return next(b for t, b in BANDS if score >= t)


def cap(b, gated):
    return "Developing" if gated and BAND_RANK[b] > BAND_RANK["Developing"] else b


def pq_urgency(sens, life):
    s = {"low": 0, "medium": 1, "high": 2}.get((sens or "").lower())
    l = {"<3y": 0, "3-10y": 1, ">10y": 2}.get((life or "").replace(" ", ""))
    if s is None or l is None:
        return None
    return ["low", "low", "medium", "high", "urgent"][s + l]


def score(data):
    errs, per = [], {d: [] for d in DOMAINS}
    for a in data.get("answers", []):
        d, sc, basis = a.get("domain"), a.get("score"), a.get("basis", "self-reported")
        if d not in DOMAINS:
            errs.append(f"{a.get('id')}: unknown domain {d}"); continue
        if not isinstance(sc, (int, float)) or not 0 <= sc <= 5:
            errs.append(f"{a.get('id')}: score must be 0-5"); continue
        if basis not in ("evidence-seen", "self-reported"):
            errs.append(f"{a.get('id')}: basis must be evidence-seen|self-reported"); continue
        if a.get("gate") and a["gate"] not in GATES:
            errs.append(f"{a.get('id')}: unknown gate {a['gate']}"); continue
        per[d].append(a)
    if errs:
        raise ValueError("; ".join(errs))
    d9 = data.get("d9_in_scope", bool(per["D9"]))
    active = [d for d in DOMAINS if (d != "D9" or d9)]
    missing = [d for d in active if not per[d]]
    if missing:
        raise ValueError(f"no answers for in-scope domains: {', '.join(missing)}")
    wsum = sum(DOMAINS[d][1] for d in active)
    domains, oc, ov = {}, 0.0, 0.0
    for d in active:
        ans = per[d]
        c = sum(a["score"] for a in ans) / len(ans) * 20
        v = sum(min(a["score"], 3) if a.get("basis") == "self-reported" else a["score"] for a in ans) / len(ans) * 20
        w = DOMAINS[d][1] * 100 / wsum
        domains[d] = {"name": DOMAINS[d][0], "weight": round(w, 2), "claimed": round(c, 1), "verified": round(v, 1),
                      "answered": len(ans), "self_reported": sum(1 for a in ans if a.get("basis") == "self-reported")}
        oc += c * w / 100
        ov += v * w / 100
    gates = sorted({GATES[a["gate"]] for d in active for a in per[d] if a.get("gate") and a["score"] <= 1})
    qa = per["D2"] + per["D4"]
    qr = sum(min(a["score"], 3) if a.get("basis") == "self-reported" else a["score"] for a in qa) / len(qa) * 20
    findings = [{"id": f"MA-{a['id']}", "check": f"maturity.{a['domain']}.{a['id']}", "target": data.get("org", ""),
                 "status": "fail" if a["score"] <= 1 else "warn", "severity": "high" if a.get("gate") or a["score"] == 0 else "medium",
                 "title": a.get("text", a["id"]), "evidence_basis": a.get("basis", "self-reported"),
                 "priority": "P0" if a.get("gate") or a["score"] == 0 else ("P1" if a["score"] == 1 else "P2"),
                 "source": "score_assessment.py/1.0"}
                for d in active for a in per[d] if a["score"] <= 2]
    return {
        "org": data.get("org", ""), "date": data.get("date", ""), "assessor": data.get("assessor", ""), "scope": data.get("scope", ""),
        "domains": domains, "overall_claimed": round(oc, 1), "overall_verified": round(ov, 1),
        "band_claimed": cap(band(oc), gates), "band_verified": cap(band(ov), gates),
        "quantum_readiness": round(qr, 1),
        "pq_urgency": pq_urgency(data.get("data_sensitivity"), data.get("data_shelf_life")),
        "gates_triggered": gates, "findings": findings,
        "disclaimer": "Heuristic maturity self-assessment; not an audit or certification. Self-reported answers capped at 3 in Verified.",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("answers")
    ap.add_argument("-o", "--output")
    a = ap.parse_args()
    try:
        res = score(json.load(open(a.answers)))
    except (ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr); return 2
    s = json.dumps(res, indent=2, ensure_ascii=False)
    if a.output:
        open(a.output, "w").write(s + "\n")
    print(s)
    return 0


if __name__ == "__main__":
    sys.exit(main())
