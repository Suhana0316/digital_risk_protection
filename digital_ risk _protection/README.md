# 🛡️ AegisGuard | Next-Gen Digital Risk Protection (DRP) Platform 2.5

> **Hackathon Edition • Standout Cyber Defense Suite**  
> An autonomous, user-understandable Digital Risk Protection platform featuring **Audible Threat Alarms**, **Real Enterprise Brand DNA Matching**, **Company Logo Abuse & Screenshot Forensics**, **Snapchat Impersonator Auditing**, an **Interactive Scam Connection Graph**, and **Bilingual Telugu + English Explanations**.

---

## 🌟 What Makes AegisGuard Stand Out in a Hackathon

Traditional security tools only protect inside corporate firewalls (antivirus, SIEMs). **Digital Risk Protection (DRP)** is the critical frontier for this and future generations:
1. 🔔 **Audible Cyber Threat Alarm & Flashing Beacon**: The instant a medium/high/critical threat is detected, an authentic dual-tone synthesized alarm siren sounds via the browser's native **Web Audio API** (with a dedicated Mute/Unmute toggle and Test Alarm button).
2. 🧬 **Brand DNA Matcher & Real Companies Database**: Audits suspect profiles and websites against authentic corporate registries (**State Bank of India, HDFC Bank, PayPal, Microsoft, Apple, Google, Amazon, Snapchat, Netflix**) to spot exact deviations in official domains, handles, and contact emails.
3. 📸 **Logo Abuse & Screenshot Scam Scanner**: Allows users to upload screenshots of fraudulent payment requests, fake WhatsApp/SMS notices, and cloned company trademark logos (fake SBI KYC alerts, deceptive payment QR codes, OTP traps).
4. 👻 **Snapchat & Multi-Platform Protection**: Comprehensive support for **Snapchat**, Instagram, X (Twitter), Facebook, Telegram, LinkedIn, YouTube, and Discord *(TikTok removed as requested)*.
5. 🕸️ **Interactive Scam Connection Graph**: Visualizes syndicated fraud networks linking target handles, phishing domains, rogue APK droppers, and fraudulent UPI hotlines with victim telemetry on a live canvas.
6. 🌐 **Cyber Safety for Everyone (Bilingual English + తెలుగు)**: Plain-language explanations and mitigation checklists in both English and Telugu so students, families, and non-technical judges can understand the risks immediately.

---

## 📊 Creative Statistical Dashboards & Visualizations

AegisGuard eliminates cybersecurity jargon with **explainable, intuitive visual telemetry**:
1. **Threat Severity Distribution** (Interactive Doughnut Chart with live severity counts: Critical, High, Medium, Low, Minimal)
2. **Attack Vectors by Platform** (Real-time distribution bar chart across Snapchat, Instagram, X, Google Play, Telegram)
3. **7-Day Threat Velocity Timeline** (Smooth spline area chart showing threat detection rate over time)
4. **Perimeter Threat Surface Radar** (Multi-vector radar chart visualizing Domain Spoofing, Brand Logo Misuse, Rogue Permissions, Phishing Keywords, and Bot Entropy)
5. **Interactive Circular Score Gauge Meter** (Dynamic SVG speedometer animating from 0 to 100 with smooth emerald ➔ amber ➔ crimson color transitions)

---

## 🧪 Comprehensive Automated Testing (36 Tests - 100% Pass Rate)

The platform is thoroughly tested with **36 automated unit and integration tests** covering all heuristics, boundaries, validation error handling, and API endpoints:

```bash
# Run the test suite
pytest -v test_drp.py
```

### Test Coverage Highlights:
- ✅ `test_snapchat_platform_support`: Verifies Snapchat is active in platform domains and TikTok is removed.
- ✅ `test_match_brand_dna_sbi_fraud`: Tests Brand DNA matching against real SBI with rogue domain and handle.
- ✅ `test_match_brand_dna_legitimate`: Tests authentic brand match with zero discrepancies.
- ✅ `test_analyze_image_and_logo_abuse`: Tests logo misuse, fake QR codes, and OTP harvesting traps.
- ✅ `test_analyze_multimodal_message_kyc_scam`: Tests urgent SMS/voice transcript coercion.
- ✅ `test_score_to_risk_boundaries`: Verifies exact scoring thresholds (Minimal, Low, Medium, High, Critical).
- ✅ `test_homoglyph_detection`: Verifies non-ASCII Cyrillic, Greek, and number-for-letter substitutions.
- ✅ `test_levenshtein_distance`: Tests string similarity distance calculation.
- ✅ `test_analyze_mobile_app_trojan_clone`: Tests dangerous Android accessibility and SMS interception flags.
- ✅ `test_analyze_typosquatting`: Tests lookalike permutation generation and candidate scoring.
- ✅ `test_generate_takedown_notice`: Verifies legal notice formatting and incident IDs.
- ✅ `test_api_*`: Tests all Flask HTTP endpoints (`/api/match-brand-dna`, `/api/analyze-image-logo`, `/api/analyze-multimodal`, `/api/registered-brands`, `/api/analyze-account`, `/api/analyze-app`, `/api/analyze-typosquat`, `/api/generate-takedown`, `/api/stats`, `/api/recent-threats`, `/api/reset-demo`, `/health`).

---

## 💻 Quick Start & Running Locally

### 1. Activate Environment & Dependencies
```bash
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the Security Command Center
```bash
python app.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your web browser.

- Visit **`/`** for the high-impact portal and telemetry ticker.
- Visit **`/dashboard`** to access the SOC command center, interactive charts, and scanners.
- Try the **⚡ Hackathon Scenarios** bar at the top (`Fake SBI Brand Phish`, `Snapchat Impersonator`, `Cloned Bank APK`) to watch the charts, animated gauges, Brand DNA, and **audible siren alarm** execute live!
