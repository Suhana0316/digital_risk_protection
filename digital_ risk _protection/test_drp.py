"""
Comprehensive Automated Test Suite for AegisGuard Digital Risk Protection (DRP) Platform.
Covers core heuristic algorithms, edge cases, mobile security scoring, homoglyphs, and Flask endpoints.
"""

import json
import unittest
from app import app
from drp_engine import (
    score_to_risk,
    calculate_levenshtein,
    calculate_similarity_ratio,
    detect_homoglyphs,
    analyze_account,
    analyze_mobile_app,
    analyze_typosquatting,
    generate_takedown_notice,
    match_brand_dna,
    analyze_image_and_logo,
    analyze_multimodal_message,
    analyze_voice_recording,
    telemetry_store,
    ThreatTelemetryStore,
    REAL_BRANDS_DATABASE,
)


class TestDRPCoreEngine(unittest.TestCase):
    """Unit tests for the heuristic threat intelligence engine."""

    def test_score_to_risk_boundaries(self):
        self.assertEqual(score_to_risk(0), "Minimal")
        self.assertEqual(score_to_risk(19), "Minimal")
        self.assertEqual(score_to_risk(20), "Low")
        self.assertEqual(score_to_risk(49), "Low")
        self.assertEqual(score_to_risk(50), "Medium")
        self.assertEqual(score_to_risk(74), "Medium")
        self.assertEqual(score_to_risk(75), "High")
        self.assertEqual(score_to_risk(89), "High")
        self.assertEqual(score_to_risk(90), "Critical")
        self.assertEqual(score_to_risk(100), "Critical")

    def test_levenshtein_distance(self):
        self.assertEqual(calculate_levenshtein("paypal", "paypal"), 0)
        self.assertEqual(calculate_levenshtein("paypal", "paypa1"), 1)
        self.assertEqual(calculate_levenshtein("google", ""), 6)
        self.assertAlmostEqual(calculate_similarity_ratio("paypal", "paypal"), 1.0)
        self.assertGreater(calculate_similarity_ratio("paypal", "paypa1"), 0.8)

    def test_homoglyph_detection(self):
        # Cyrillic 'а' (\u0430) vs Latin 'a'
        text_with_cyrillic = "p\u0430ypal"
        normalized, detected = detect_homoglyphs(text_with_cyrillic)
        self.assertEqual(normalized, "paypal")
        self.assertTrue(len(detected) > 0)
        self.assertEqual(detected[0]["char"], "\u0430")

        # Number substitution '0' for 'o'
        norm2, det2 = detect_homoglyphs("micr0s0ft")
        self.assertEqual(norm2, "microsoft")
        self.assertEqual(len(det2), 2)

    def test_analyze_account_verified_profile(self):
        payload = {
            "platform": "instagram",
            "username": "apexbankofficial",
            "profile_url": "https://instagram.com/apexbankofficial",
            "official_username": "apexbankofficial",
            "brand_name": "Apex Bank",
        }
        res, status = analyze_account(payload)
        self.assertEqual(status, 200)
        self.assertEqual(res["risk_level"], "Minimal")
        self.assertLessEqual(res["score"], 20)
        self.assertFalse(res["is_impersonation"])

    def test_analyze_account_high_risk_impersonator(self):
        payload = {
            "platform": "instagram",
            "username": "apexbank_official_helpdesk_support_99831",
            "profile_url": "https://phishing-site.com/apexbank",
            "official_username": "apexbank",
            "brand_name": "Apex Bank",
            "bio": "Official support! DM for immediate account recovery and giveaway!",
        }
        res, status = analyze_account(payload)
        self.assertEqual(status, 200)
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertGreaterEqual(res["score"], 75)
        self.assertTrue(res["is_impersonation"])
        self.assertIn("vector_breakdown", res)
        self.assertGreater(res["vector_breakdown"]["domain_spoofing"], 0)
        self.assertGreater(res["vector_breakdown"]["phishing_keywords"], 0)

    def test_analyze_account_validation_errors(self):
        # Invalid data type
        res, status = analyze_account("not-a-dict")
        self.assertEqual(status, 400)

        # Unsupported platform
        res, status = analyze_account({"platform": "myspace", "username": "test"})
        self.assertEqual(status, 400)

        # Missing username
        res, status = analyze_account({"platform": "instagram", "username": ""})
        self.assertEqual(status, 400)

        # Malformed profile url
        res, status = analyze_account({
            "platform": "instagram",
            "username": "tester",
            "profile_url": "not-a-valid-url"
        })
        self.assertEqual(status, 400)

    def test_analyze_mobile_app_legitimate(self):
        payload = {
            "brand_name": "Apex Bank",
            "app_name": "Apex Bank Mobile",
            "app_store": "Google Play",
            "developer_name": "Apex Bank Digital Ltd",
            "developer_email": "security@apexbank.com",
            "package_id": "com.apexbank.mobile",
            "permissions": ["ACCESS_FINE_LOCATION"],
        }
        res, status = analyze_mobile_app(payload)
        self.assertEqual(status, 200)
        self.assertLessEqual(res["score"], 30)
        self.assertIn(res["risk_level"], ["Minimal", "Low"])

    def test_analyze_mobile_app_trojan_clone(self):
        payload = {
            "brand_name": "Apex Bank",
            "app_name": "Apex Bank MOD APK",
            "app_store": "APKPure",
            "developer_name": "Fast App Modder",
            "developer_email": "modder@gmail.com",
            "package_id": "com.apexbank.mod.hack",
            "permissions": [
                "BIND_ACCESSIBILITY_SERVICE",
                "RECEIVE_SMS",
                "SYSTEM_ALERT_WINDOW",
                "REQUEST_INSTALL_PACKAGES",
            ],
        }
        res, status = analyze_mobile_app(payload)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(res["score"], 75)
        self.assertIn(res["risk_level"], ["High", "Critical"])
        self.assertGreater(res["dangerous_permissions_count"], 0)

    def test_analyze_mobile_app_validation_error(self):
        res, status = analyze_mobile_app({})
        self.assertEqual(status, 400)

    def test_analyze_typosquatting(self):
        res, status = analyze_typosquatting("paypal.com")
        self.assertEqual(status, 200)
        self.assertGreater(res["variants_detected"], 0)
        self.assertTrue(any("login-" in t["domain"] or "0" in t["domain"] for t in res["threats"]))

        # Custom candidates testing
        custom_candidates = ["p\u0430ypal.com", "paypal-security.net", "randomsite.org"]
        res2, status2 = analyze_typosquatting("paypal", custom_candidates)
        self.assertEqual(status2, 200)
        self.assertEqual(len(res2["threats"]), 3)

    def test_generate_takedown_notice(self):
        payload = {
            "brand_name": "Apex Bank",
            "platform": "Instagram",
            "target_identifier": "@apex_bank_fake",
            "score": 92,
        }
        res, status = generate_takedown_notice(payload)
        self.assertEqual(status, 200)
        self.assertIn("DRP-INC-", res["incident_id"])
        self.assertIn("LEGAL NOTICE", res["notice_text"])
        self.assertIn("Apex Bank", res["notice_text"])

    def test_telemetry_store(self):
        store = ThreatTelemetryStore()
        initial_count = len(store.incidents)
        stats = store.get_stats()
        self.assertEqual(stats["total_scans"], initial_count)
        self.assertIn("platform_breakdown", stats)
        self.assertIn("risk_distribution", stats)

        # Add new incident
        store.add_incident({
            "type": "social_account",
            "platform": "Instagram",
            "target": "@test_scammer",
            "brand": "Test Brand",
            "score": 95,
            "risk_level": "Critical",
        })
        new_stats = store.get_stats()
        self.assertEqual(new_stats["total_scans"], initial_count + 1)
        self.assertGreaterEqual(new_stats["critical_risk"], 1)

        # Reset
        store.reset()
        self.assertEqual(len(store.incidents), initial_count)

    def test_analyze_account_bot_digits_entropy(self):
        payload = {
            "platform": "x",
            "username": "crypto_user_984729104",
            "brand_name": "Crypto",
        }
        res, status = analyze_account(payload)
        self.assertEqual(status, 200)
        self.assertGreater(res["vector_breakdown"]["synthetic_behavior"], 0)
        self.assertTrue(any("Synthetic Pattern" in ind for ind in res["indicators"]))

    def test_analyze_account_bio_scam_lure(self):
        payload = {
            "platform": "telegram",
            "username": "support_agent",
            "brand_name": "Coinbase",
            "bio": "Official backup account. DM for recovery and claim reward here!",
        }
        res, status = analyze_account(payload)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(res["score"], 30)
        self.assertTrue(any("Scam Lure in Bio" in ind for ind in res["indicators"]))

    def test_analyze_mobile_app_package_id_mod(self):
        payload = {
            "brand_name": "SuperGame",
            "app_name": "SuperGame Free Coins",
            "app_store": "APKPure",
            "package_id": "com.supergame.free.mod",
        }
        res, status = analyze_mobile_app(payload)
        self.assertEqual(status, 200)
        self.assertTrue(any("Tampered Package ID" in ind for ind in res["indicators"]))

    def test_analyze_typosquatting_empty_brand(self):
        res, status = analyze_typosquatting("")
        self.assertEqual(status, 400)
        self.assertIn("error", res)

    def test_takedown_default_values(self):
        res, status = generate_takedown_notice({})
        self.assertEqual(status, 200)
        self.assertIn("DRP-INC-", res["incident_id"])
        self.assertIn("LEGAL NOTICE", res["notice_text"])

    def test_snapchat_platform_support(self):
        # TikTok removed, Snapchat supported
        from drp_engine import PLATFORM_DOMAINS
        self.assertIn("snapchat", PLATFORM_DOMAINS)
        self.assertNotIn("tiktok", PLATFORM_DOMAINS)

        payload = {
            "platform": "snapchat",
            "username": "snapchat_streak_bot_support",
            "profile_url": "https://phishing-snapchat.xyz/login",
            "brand_name": "Snapchat",
            "official_username": "snapchat",
            "bio": "DM for recovery!",
        }
        res, status = analyze_account(payload)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(res["score"], 50)
        self.assertTrue(res["trigger_alarm"])
        self.assertIn("snapchat", res["platform"])

    def test_match_brand_dna_sbi_fraud(self):
        payload = {
            "brand_name": "State Bank of India",
            "domain": "sbi-kyc-update-portal.net",
            "handle": "sbi_support_urgent",
            "email": "sbi.helpdesk2026@gmail.com",
            "platform": "web",
        }
        res, status = match_brand_dna(payload)
        self.assertEqual(status, 200)
        self.assertEqual(res["status"], "matched")
        self.assertTrue(res["is_fraudulent_clone"])
        self.assertGreaterEqual(res["score"], 50)
        self.assertTrue(res["trigger_alarm"])
        self.assertIn("telugu_summary", res)
        self.assertGreater(len(res["discrepancies"]), 0)

    def test_match_brand_dna_legitimate(self):
        payload = {
            "brand_name": "PayPal",
            "domain": "paypal.com",
            "handle": "paypal",
            "platform": "twitter",
        }
        res, status = match_brand_dna(payload)
        self.assertEqual(status, 200)
        self.assertFalse(res["is_fraudulent_clone"])
        self.assertEqual(len(res["discrepancies"]), 0)

    def test_analyze_image_and_logo_abuse(self):
        payload = {
            "filename": "fake_sbi_payment.png",
            "brand_name": "State Bank of India (SBI)",
            "extracted_text": "Transfer Rs. 5000 to UPI ID verify@okaxis. Share OTP immediately to prevent electricity disconnected.",
        }
        res, status = analyze_image_and_logo(payload)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(res["score"], 70)
        self.assertTrue(res["trigger_alarm"])
        self.assertTrue(res["has_urgent_payment"])
        self.assertTrue(res["has_otp_harvesting"])
        self.assertIn("telugu_explanation", res)

    def test_analyze_multimodal_message_kyc_scam(self):
        payload = {
            "message": "Dear customer your account KYC expired immediately click http://bank-update.xyz to avoid electricity cut off. Call +919847291044",
            "source_type": "sms",
        }
        res, status = analyze_multimodal_message(payload)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(res["score"], 50)
        self.assertTrue(res["trigger_alarm"])
        self.assertGreater(len(res["extracted_urls"]), 0)
        self.assertGreater(len(res["extracted_phones"]), 0)


class TestFlaskEndpoints(unittest.TestCase):
    """Integration tests for web and API routes."""

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_landing_page(self):
        response = self.app.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"AegisGuard", response.data)
        self.assertIn(b"Total Monitored Assets", response.data)

    def test_dashboard_page(self):
        response = self.app.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Digital Risk Protection SOC", response.data)
        self.assertIn(b"severityDoughnutChart", response.data)

    def test_api_analyze_account_endpoint(self):
        payload = {
            "platform": "instagram",
            "username": "bank_security_support_official",
            "profile_url": "https://instagram.com/bank_security_support_official",
            "brand_name": "Global Bank",
        }
        response = self.app.post(
            "/api/analyze-account",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("score", data)
        self.assertIn("risk_level", data)
        self.assertIn("vector_breakdown", data)

    def test_api_analyze_app_endpoint(self):
        payload = {
            "brand_name": "CryptoPay",
            "app_name": "CryptoPay Wallet Free Coins",
            "app_store": "APKPure",
            "permissions": ["BIND_ACCESSIBILITY_SERVICE", "RECEIVE_SMS"],
        }
        response = self.app.post(
            "/api/analyze-app",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("score", data)
        self.assertIn("dangerous_permissions_count", data)

    def test_api_analyze_typosquat_endpoint(self):
        payload = {"brand_name": "netflix.com"}
        response = self.app.post(
            "/api/analyze-typosquat",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("threats", data)
        self.assertGreater(data["variants_detected"], 0)

    def test_api_generate_takedown_endpoint(self):
        payload = {
            "brand_name": "Apex Bank",
            "platform": "X",
            "target_identifier": "@apex_scam",
            "score": 90,
        }
        response = self.app.post(
            "/api/generate-takedown",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("notice_text", data)
        self.assertIn("DRP-INC-", data["incident_id"])

    def test_api_stats_endpoint(self):
        response = self.app.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("total_scans", data)
        self.assertIn("risk_distribution", data)
        self.assertIn("platform_breakdown", data)

    def test_api_recent_threats_endpoint(self):
        response = self.app.get("/api/recent-threats?limit=5")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("incidents", data)
        self.assertLessEqual(len(data["incidents"]), 5)

    def test_api_reset_demo_endpoint(self):
        response = self.app.post("/api/reset-demo")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "success")

    def test_health_check_endpoint(self):
        response = self.app.get("/health")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "healthy")

    def test_api_registered_brands_endpoint(self):
        response = self.app.get("/api/registered-brands")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("brands", data)
        self.assertTrue(len(data["brands"]) >= 5)

    def test_api_match_brand_dna_endpoint(self):
        payload = {
            "brand_name": "State Bank of India",
            "domain": "sbi-kyc-update-portal.net",
            "handle": "sbi_support_urgent",
            "email": "sbi.helpdesk2026@gmail.com",
            "platform": "web",
        }
        response = self.app.post(
            "/api/match-brand-dna",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "matched")
        self.assertTrue(data["is_fraudulent_clone"])

    def test_api_analyze_image_logo_endpoint(self):
        payload = {
            "filename": "fake_sbi_notice.png",
            "brand_name": "State Bank of India (SBI)",
            "extracted_text": "Transfer money to UPI verify@okaxis immediately or account blocked.",
        }
        response = self.app.post(
            "/api/analyze-image-logo",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertGreaterEqual(data["score"], 50)
        self.assertTrue(data["trigger_alarm"])

    def test_api_analyze_multimodal_endpoint(self):
        payload = {
            "message": "URGENT: KYC expired. Call +919847291044 or power will be cut off.",
            "source_type": "sms",
        }
        response = self.app.post(
            "/api/analyze-multimodal",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertGreaterEqual(data["score"], 50)
        self.assertTrue(data["trigger_alarm"])

    def test_analyze_voice_recording_digital_arrest(self):
        payload = {
            "caller_id": "Inspector Sharma / Mumbai Police (+919876543210)",
            "transcript": "You are under digital arrest by CBI and Mumbai police for money laundering and narcotics parcel. Stay on video call and do not disconnect.",
            "duration_seconds": 25,
        }
        res, status = analyze_voice_recording(payload)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(res["score"], 75)
        self.assertTrue(res["is_voice_scam"])
        self.assertTrue(res["trigger_alarm"])
        self.assertIn("డిజిటల్ అరెస్ట్", res["telugu_warning"])
        self.assertIn("coercion_tactics", res)
        self.assertTrue(len(res["coercion_tactics"]) > 0)

    def test_analyze_voice_recording_bank_otp(self):
        payload = {
            "caller_id": "Bank Helpdesk Manager",
            "transcript": "Hello, this is your bank manager. Share your 6 digit OTP or your debit card will be blocked immediately.",
            "duration_seconds": 18,
        }
        res, status = analyze_voice_recording(payload)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(res["score"], 50)
        self.assertTrue(res["trigger_alarm"])
        self.assertIn("OTP", res["telugu_warning"])

    def test_analyze_voice_recording_safe(self):
        payload = {
            "caller_id": "Grocery Delivery",
            "transcript": "Hello sir, I am near your gate with your delivery order. Please collect it.",
            "duration_seconds": 10,
        }
        res, status = analyze_voice_recording(payload)
        self.assertEqual(status, 200)
        self.assertLess(res["score"], 50)
        self.assertFalse(res["trigger_alarm"])

    def test_api_analyze_voice_endpoint(self):
        payload = {
            "caller_id": "Fake CBI Officer",
            "transcript": "This is CBI officer. Arrest warrant is issued against you. You are under digital arrest.",
        }
        response = self.app.post(
            "/api/analyze-voice",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertGreaterEqual(data["score"], 70)
        self.assertTrue(data["trigger_alarm"])
        self.assertIn("telugu_warning", data)

    def test_telugu_warnings_and_alarm_across_all_modules(self):
        # 1. Social
        r_soc, _ = analyze_account({
            "platform": "snapchat",
            "username": "snapchat_helpdesk_support_urgent_99831",
            "official_username": "snapchat"
        })
        self.assertTrue(r_soc["trigger_alarm"])
        self.assertIn("హెచ్చరిక", r_soc["telugu_warning"])

        # 2. App
        r_app, _ = analyze_mobile_app({
            "brand_name": "Apex Bank",
            "app_name": "Apex Bank MOD APK",
            "app_store": "APKPure",
            "permissions": ["BIND_ACCESSIBILITY_SERVICE", "RECEIVE_SMS"]
        })
        self.assertTrue(r_app["trigger_alarm"])
        self.assertIn("హెచ్చరిక", r_app["telugu_warning"])

        # 3. Brand DNA
        r_dna, _ = match_brand_dna({
            "brand_name": "State Bank of India",
            "domain": "sbi-kyc-update-portal.net",
            "handle": "sbi_help_fake"
        })
        self.assertTrue(r_dna["trigger_alarm"])
        self.assertIn("హెచ్చరిక", r_dna["telugu_warning"])

        # 4. Multimodal Image / Logo
        r_img, _ = analyze_image_and_logo({
            "brand_name": "State Bank of India (SBI)",
            "extracted_text": "Transfer money to UPI immediately or account blocked."
        })
        self.assertTrue(r_img["trigger_alarm"])
        self.assertIn("హెచ్చరిక", r_img["telugu_warning"])

        # 5. Typosquat
        r_typo, _ = analyze_typosquatting("paypal.com")
        self.assertTrue(r_typo["trigger_alarm"])
        self.assertIn("హెచ్చరిక", r_typo["telugu_warning"])

        # 6. Voice
        r_voice, _ = analyze_voice_recording({
            "caller_id": "Fake CBI",
            "transcript": "Arrest warrant digital arrest by police."
        })
        self.assertTrue(r_voice["trigger_alarm"])
        self.assertIn("హెచ్చరిక", r_voice["telugu_warning"])


if __name__ == "__main__":
    unittest.main()
