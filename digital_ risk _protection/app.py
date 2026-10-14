from flask import Flask, jsonify, render_template, request
import os
from drp_engine import (
    analyze_account,
    analyze_mobile_app,
    analyze_typosquatting,
    match_brand_dna,
    analyze_image_and_logo,
    analyze_multimodal_message,
    analyze_voice_recording,
    generate_takedown_notice,
    telemetry_store,
    REAL_BRANDS_DATABASE,
)

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route("/")
def index():
    """High-impact welcome and overview portal."""
    stats = telemetry_store.get_stats()
    return render_template("index.html", stats=stats)


@app.route("/dashboard")
def dashboard():
    """Main Cyber Security Operations Dashboard."""
    stats = telemetry_store.get_stats()
    recent = telemetry_store.get_recent(limit=10)
    brands = list(REAL_BRANDS_DATABASE.keys())
    return render_template("dashboard.html", stats=stats, recent=recent, brands=brands)


@app.route("/api/registered-brands", methods=["GET"])
def api_get_registered_brands():
    """Returns the database of real enterprise brands for Brand DNA checking."""
    return jsonify({
        "brands": [
            {
                "id": k,
                "display_name": v["display_name"],
                "industry": v["industry"],
                "official_domains": v["official_domains"],
                "official_handles": v["official_handles"],
                "telugu_name": v.get("telugu_name", ""),
            }
            for k, v in REAL_BRANDS_DATABASE.items()
        ]
    })


@app.route("/api/match-brand-dna", methods=["POST"])
def api_match_brand_dna():
    """Compares suspect profile or domain against real enterprise brand DNA."""
    payload = request.get_json(silent=True) or {}
    result, status = match_brand_dna(payload)
    if status == 200 and result.get("score", 0) >= 50:
        telemetry_store.add_incident({
            "type": "brand_dna",
            "platform": payload.get("platform", "Web/Social").capitalize(),
            "target": payload.get("handle") or payload.get("domain") or "Suspect Clone",
            "brand": result.get("real_brand") or payload.get("brand_name", "Unknown"),
            "score": result.get("score", 75),
            "risk_level": result.get("risk_level", "High"),
            "indicators": [d.get("note", "") for d in result.get("discrepancies", [])[:3]],
            "status": "Fraud Clone Flagged",
        })
    return jsonify(result), status


@app.route("/api/analyze-image-logo", methods=["POST"])
def api_analyze_image_logo():
    """Audits uploaded screenshot or company logo for brand trademark misuse."""
    payload = request.get_json(silent=True) or {}
    result, status = analyze_image_and_logo(payload)
    if status == 200 and result.get("score", 0) >= 50:
        brand_name = result["detected_logos"][0]["brand"] if result.get("detected_logos") else "Enterprise Brand"
        telemetry_store.add_incident({
            "type": "multimodal_image",
            "platform": "Screenshot / Logo",
            "target": result.get("filename", "Uploaded Image"),
            "brand": brand_name,
            "score": result.get("score", 80),
            "risk_level": result.get("risk_level", "High"),
            "indicators": result.get("scam_vectors", [])[:3],
            "status": "Trademark Abuse Logged",
        })
    return jsonify(result), status


@app.route("/api/analyze-multimodal", methods=["POST"])
def api_analyze_multimodal():
    """Audits suspicious SMS text, WhatsApp forward, or voice call audio transcript."""
    payload = request.get_json(silent=True) or {}
    result, status = analyze_multimodal_message(payload)
    if status == 200 and result.get("score", 0) >= 50:
        telemetry_store.add_incident({
            "type": "multimodal_message",
            "platform": result.get("source_type", "SMS / WhatsApp").upper(),
            "target": (result.get("extracted_phones") or ["Suspicious Message"])[0],
            "brand": "Consumer Protection",
            "score": result.get("score", 75),
            "risk_level": result.get("risk_level", "High"),
            "indicators": result.get("detected_flags", [])[:3],
            "status": "Scam Coercion Detected",
        })
    return jsonify(result), status


@app.route("/api/analyze-voice", methods=["POST"])
def api_analyze_voice():
    """Audits live user voice recording or transcript for extortion, digital arrest, and OTP phishing."""
    payload = request.get_json(silent=True) or {}
    result, status = analyze_voice_recording(payload)
    if status == 200 and result.get("score", 0) >= 50:
        telemetry_store.add_incident({
            "type": "voice_scam",
            "platform": "Voice Audio",
            "target": payload.get("caller_id") or payload.get("caller_claimed_id") or "Incoming Voice Call",
            "brand": result.get("scam_category") or "Audio Defense",
            "score": result.get("score", 85),
            "risk_level": result.get("risk_level", "High"),
            "indicators": result.get("threat_vectors", [])[:3],
            "status": "Audio Threat Escalate",
        })
    return jsonify(result), status


@app.route("/api/analyze-account", methods=["POST"])
def api_analyze_account():
    """Analyzes a suspicious social account and records telemetry."""
    payload = request.get_json(silent=True) or {}
    result, status = analyze_account(payload)
    if status == 200:
        telemetry_store.add_incident({
            "type": "social_account",
            "platform": result.get("platform", "Social").capitalize(),
            "target": f"@{result.get('username', '')}",
            "brand": result.get("brand_name") or "Unspecified",
            "score": result.get("score", 0),
            "risk_level": result.get("risk_level", "Low"),
            "indicators": result.get("indicators", [])[:3],
            "status": "Takedown Recommended" if result.get("score", 0) >= 75 else "Analyzed & Logged",
        })
    return jsonify(result), status


@app.route("/api/analyze-app", methods=["POST"])
def api_analyze_app():
    """Analyzes a mobile application package or listing and records telemetry."""
    payload = request.get_json(silent=True) or {}
    result, status = analyze_mobile_app(payload)
    if status == 200:
        telemetry_store.add_incident({
            "type": "mobile_app",
            "platform": result.get("app_store", "Mobile Store"),
            "target": result.get("app_name", "Application"),
            "brand": result.get("brand_name") or "Unspecified",
            "score": result.get("score", 0),
            "risk_level": result.get("risk_level", "Low"),
            "indicators": result.get("indicators", [])[:3],
            "status": "App Store Escalation" if result.get("score", 0) >= 75 else "Analyzed & Logged",
        })
    return jsonify(result), status


@app.route("/api/analyze-typosquat", methods=["POST"])
def api_analyze_typosquat():
    """Detects brand homoglyph and typosquatting domain attacks."""
    payload = request.get_json(silent=True) or {}
    target_brand = payload.get("brand_name") or payload.get("domain") or ""
    candidate_domains = payload.get("candidate_domains")
    result, status = analyze_typosquatting(target_brand, candidate_domains)
    return jsonify(result), status


@app.route("/api/generate-takedown", methods=["POST"])
def api_generate_takedown():
    """Generates a professional 1-click Cease & Desist / DMCA Takedown Notice."""
    payload = request.get_json(silent=True) or {}
    result, status = generate_takedown_notice(payload)
    return jsonify(result), status


@app.route("/api/stats", methods=["GET"])
def api_get_stats():
    """Returns live aggregated statistics for charts and telemetry widgets."""
    return jsonify(telemetry_store.get_stats())


@app.route("/api/recent-threats", methods=["GET"])
def api_get_recent():
    """Returns the most recent detected threat incidents."""
    limit = request.args.get("limit", default=10, type=int)
    return jsonify({"incidents": telemetry_store.get_recent(limit=limit)})


@app.route("/api/reset-demo", methods=["POST"])
def api_reset_demo():
    """Resets telemetry store back to baseline demonstration incidents."""
    telemetry_store.reset()
    return jsonify({"status": "success", "message": "Demo telemetry dataset restored."})


@app.route("/health")
def health_check():
    """Health inspection probe."""
    return jsonify({"status": "healthy", "service": "Digital Risk Protection Engine", "version": "2.5-Hackathon-Pro"})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)