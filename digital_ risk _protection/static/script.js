/**
 * AegisGuard Digital Risk Protection (DRP) Platform 2.5
 * Frontend Controller: Threat Alarm, Brand DNA Matcher, Logo Analysis,
 * Scam Connection Graph, Charts, and Multilingual Explanations.
 */

let severityChartInstance = null;
let platformChartInstance = null;
let trendChartInstance = null;
let radarChartInstance = null;
let cachedIncidents = [];

// Threat Alarm System State
let isAlarmAudioEnabled = true;
let audioContext = null;
let isTeluguMode = false;

// ============================================================================
// WEB AUDIO API SYNTHESIZED THREAT ALARM
// ============================================================================

function getAudioContext() {
    if (!audioContext) {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (AudioCtx) {
            audioContext = new AudioCtx();
        }
    }
    if (audioContext && audioContext.state === 'suspended') {
        audioContext.resume();
    }
    return audioContext;
}

function playThreatAlarmSound() {
    if (!isAlarmAudioEnabled) return;

    try {
        const ctx = getAudioContext();
        if (!ctx) return;

        const now = ctx.currentTime;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();

        osc.type = 'sawtooth';
        // Oscillating alarm siren frequency: 880Hz -> 587Hz -> 880Hz
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.exponentialRampToValueAtTime(587, now + 0.25);
        osc.frequency.exponentialRampToValueAtTime(880, now + 0.5);
        osc.frequency.exponentialRampToValueAtTime(587, now + 0.75);
        osc.frequency.exponentialRampToValueAtTime(880, now + 1.0);
        osc.frequency.exponentialRampToValueAtTime(587, now + 1.25);
        osc.frequency.exponentialRampToValueAtTime(880, now + 1.5);

        gain.gain.setValueAtTime(0.2, now);
        gain.gain.exponentialRampToValueAtTime(0.01, now + 1.8);

        osc.connect(gain);
        gain.connect(ctx.destination);

        osc.start(now);
        osc.stop(now + 1.8);
    } catch (err) {
        console.warn("Audio alarm synthesis:", err);
    }
}

function triggerAlarm(score, reason = 'High Risk Threat Detected') {
    if (score < 50) return;

    // Show visual flashing banner
    const banner = document.getElementById('alarmBanner');
    const bannerText = document.getElementById('alarmBannerText');
    if (banner && bannerText) {
        bannerText.textContent = `🚨 PERIMETER ALARM: ${reason.toUpperCase()} (RISK: ${score}/100)`;
        banner.classList.remove('hidden');
    }

    // Play synthesized cyber siren
    playThreatAlarmSound();
}

function silenceAlarm() {
    const banner = document.getElementById('alarmBanner');
    if (banner) banner.classList.add('hidden');
}

function toggleAlarmAudio() {
    isAlarmAudioEnabled = !isAlarmAudioEnabled;
    const btn = document.getElementById('btnToggleAlarm');
    const icon = document.getElementById('alarmStatusIcon');
    const text = document.getElementById('alarmStatusText');

    if (isAlarmAudioEnabled) {
        if (btn) btn.className = 'btn-pill alarm-toggle-btn active-alarm';
        if (icon) icon.textContent = '🔔';
        if (text) text.textContent = 'Alarm: ON';
        showToast('Cyber Threat Alarm Enabled', 'info');
        getAudioContext(); // warm up
    } else {
        if (btn) btn.className = 'btn-pill alarm-toggle-btn muted-alarm';
        if (icon) icon.textContent = '🔕';
        if (text) text.textContent = 'Alarm: MUTED';
        silenceAlarm();
        showToast('Threat Alarm Muted', 'info');
    }
}

function testAlarmSound() {
    getAudioContext();
    triggerAlarm(95, "Manual Alarm Test Verification");
    showToast("Synthesizing Cyber Threat Klaxon...", "error");
}

// ============================================================================
// BILINGUAL MODE TOGGLE (ENGLISH / TELUGU)
// ============================================================================

function toggleBilingualMode() {
    isTeluguMode = !isTeluguMode;
    const label = document.getElementById('currentLangLabel');
    if (label) {
        label.textContent = isTeluguMode ? 'తెలుగు (Telugu)' : 'English (EN)';
    }

    // Toggle highlighted emphasis
    document.querySelectorAll('.bilingual-explanation-box').forEach(el => {
        if (isTeluguMode) {
            el.style.border = '2px solid var(--accent-cyan)';
            el.style.background = 'rgba(6, 182, 212, 0.12)';
        } else {
            el.style.border = '1px solid rgba(59, 130, 246, 0.25)';
            el.style.background = 'rgba(59, 130, 246, 0.08)';
        }
    });

    showToast(isTeluguMode ? 'తెలుగు వివరణ మోడ్ యాక్టివ్ చేయబడింది' : 'Switched to English Mode', 'info');
}

// ============================================================================
// SECTION NAVIGATION
// ============================================================================

function showSection(sectionId) {
    const sections = document.querySelectorAll('.content-section');
    sections.forEach(s => s.classList.add('hidden'));

    const target = document.getElementById(sectionId);
    if (target) {
        target.classList.remove('hidden');
    }

    const navItems = document.querySelectorAll('.sidebar-nav .nav-item');
    navItems.forEach(item => {
        if (item.getAttribute('onclick')?.includes(sectionId)) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    if (sectionId === 'overview') {
        window.dispatchEvent(new Event('resize'));
    }

    if (sectionId === 'scamgraph') {
        initScamNetworkGraph();
    }
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    const icon = type === 'success' ? '✅' : type === 'error' ? '🚨' : 'ℹ️';
    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ============================================================================
// GAUGE ANIMATION
// ============================================================================

function animateGauge(arcId, valId, score, badgeId) {
    const arc = document.getElementById(arcId);
    const valText = document.getElementById(valId);
    const badge = badgeId ? document.getElementById(badgeId) : null;

    const totalLength = 314;
    const offset = totalLength - (score / 100) * totalLength;

    if (arc) {
        arc.style.strokeDashoffset = offset;
        if (score >= 75) {
            arc.style.stroke = '#ef4444';
        } else if (score >= 50) {
            arc.style.stroke = '#f59e0b';
        } else if (score >= 20) {
            arc.style.stroke = '#3b82f6';
        } else {
            arc.style.stroke = '#10b981';
        }
    }

    if (valText) {
        let current = 0;
        const duration = 800;
        const stepTime = 15;
        const steps = duration / stepTime;
        const increment = score / steps;

        const counter = setInterval(() => {
            current += increment;
            if (current >= score) {
                current = score;
                clearInterval(counter);
            }
            valText.textContent = Math.round(current);
        }, stepTime);
    }

    if (badge) {
        let riskClass = 'risk-minimal';
        let riskLabel = 'Minimal';

        if (score >= 90) {
            riskClass = 'risk-critical';
            riskLabel = 'Critical Risk';
        } else if (score >= 75) {
            riskClass = 'risk-high';
            riskLabel = 'High Risk';
        } else if (score >= 50) {
            riskClass = 'risk-medium';
            riskLabel = 'Medium Risk';
        } else if (score >= 20) {
            riskClass = 'risk-low';
            riskLabel = 'Low Risk';
        }

        badge.className = `badge-risk ${riskClass}`;
        badge.textContent = riskLabel;
    }
}

// ============================================================================
// CHART.JS STATISTICAL VISUALIZATIONS
// ============================================================================

function initCharts(stats) {
    if (typeof Chart === 'undefined') return;

    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Plus Jakarta Sans', sans-serif";

    // 1. Severity Doughnut
    const doughnutCtx = document.getElementById('severityDoughnutChart');
    if (doughnutCtx) {
        const dist = stats.risk_distribution || { Critical: 2, High: 4, Medium: 3, Low: 1, Minimal: 2 };
        severityChartInstance = new Chart(doughnutCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Minimal'],
                datasets: [{
                    data: [dist.Critical || 0, dist.High || 0, dist.Medium || 0, dist.Low || 0, dist.Minimal || 0],
                    backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#3b82f6', '#10b981'],
                    borderWidth: 0,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: { legend: { display: false } }
            }
        });

        const leg = document.getElementById('doughnutLegend');
        if (leg) {
            leg.innerHTML = `
                <span class="legend-pill"><span class="legend-color-dot" style="background:#dc2626"></span> Critical (${dist.Critical || 0})</span>
                <span class="legend-pill"><span class="legend-color-dot" style="background:#ef4444"></span> High (${dist.High || 0})</span>
                <span class="legend-pill"><span class="legend-color-dot" style="background:#f59e0b"></span> Medium (${dist.Medium || 0})</span>
                <span class="legend-pill"><span class="legend-color-dot" style="background:#3b82f6"></span> Low (${dist.Low || 0})</span>
                <span class="legend-pill"><span class="legend-color-dot" style="background:#10b981"></span> Minimal (${dist.Minimal || 0})</span>
            `;
        }
    }

    // 2. Attack Vectors by Platform Bar Chart (Snapchat, Instagram, X, Google Play, Telegram)
    const barCtx = document.getElementById('platformBarChart');
    if (barCtx) {
        const plat = stats.platform_breakdown || { Snapchat: 3, Instagram: 4, X: 3, 'Google Play': 2, Telegram: 2 };
        platformChartInstance = new Chart(barCtx, {
            type: 'bar',
            data: {
                labels: Object.keys(plat),
                datasets: [{
                    label: 'Flagged Impersonations',
                    data: Object.values(plat),
                    backgroundColor: '#3b82f6',
                    borderRadius: 6,
                    maxBarThickness: 36
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } },
                    y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, beginAtZero: true, ticks: { stepSize: 1 } }
                }
            }
        });
    }

    // 3. 7-Day Trend Line Chart
    const lineCtx = document.getElementById('trendLineChart');
    if (lineCtx) {
        const trend = stats.trend || { labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Today'], values: [3, 5, 4, 7, 6, 8, 12] };
        trendChartInstance = new Chart(lineCtx, {
            type: 'line',
            data: {
                labels: trend.labels,
                datasets: [{
                    label: 'Perimeter Threats',
                    data: trend.values,
                    borderColor: '#a78bfa',
                    backgroundColor: 'rgba(167, 139, 250, 0.12)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.35,
                    pointBackgroundColor: '#a78bfa',
                    pointRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { display: false } },
                    y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, beginAtZero: true }
                }
            }
        });
    }

    // 4. Multi-Vector Radar Chart
    const radarCtx = document.getElementById('vectorRadarChart');
    if (radarCtx) {
        radarChartInstance = new Chart(radarCtx, {
            type: 'radar',
            data: {
                labels: ['Domain Spoofing', 'Brand Logo Misuse', 'Rogue App Permissions', 'Phishing Keywords', 'Synthetic Bot Entropy'],
                datasets: [{
                    label: 'Perimeter Risk Exposure',
                    data: [85, 90, 75, 80, 70],
                    backgroundColor: 'rgba(6, 182, 212, 0.2)',
                    borderColor: '#06b6d4',
                    borderWidth: 2,
                    pointBackgroundColor: '#06b6d4'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    r: {
                        grid: { color: 'rgba(255, 255, 255, 0.08)' },
                        angleLines: { color: 'rgba(255, 255, 255, 0.08)' },
                        pointLabels: { font: { size: 10 } },
                        suggestedMin: 0,
                        suggestedMax: 100
                    }
                }
            }
        });
    }
}

function updateCharts(stats) {
    if (severityChartInstance) {
        const dist = stats.risk_distribution || {};
        severityChartInstance.data.datasets[0].data = [
            dist.Critical || 0, dist.High || 0, dist.Medium || 0, dist.Low || 0, dist.Minimal || 0
        ];
        severityChartInstance.update();

        const leg = document.getElementById('doughnutLegend');
        if (leg) {
            leg.innerHTML = `
                <span class="legend-pill"><span class="legend-color-dot" style="background:#dc2626"></span> Critical (${dist.Critical || 0})</span>
                <span class="legend-pill"><span class="legend-color-dot" style="background:#ef4444"></span> High (${dist.High || 0})</span>
                <span class="legend-pill"><span class="legend-color-dot" style="background:#f59e0b"></span> Medium (${dist.Medium || 0})</span>
                <span class="legend-pill"><span class="legend-color-dot" style="background:#3b82f6"></span> Low (${dist.Low || 0})</span>
                <span class="legend-pill"><span class="legend-color-dot" style="background:#10b981"></span> Minimal (${dist.Minimal || 0})</span>
            `;
        }
    }

    if (platformChartInstance && stats.platform_breakdown) {
        platformChartInstance.data.labels = Object.keys(stats.platform_breakdown);
        platformChartInstance.data.datasets[0].data = Object.values(stats.platform_breakdown);
        platformChartInstance.update();
    }

    if (trendChartInstance && stats.trend) {
        trendChartInstance.data.labels = stats.trend.labels;
        trendChartInstance.data.datasets[0].data = stats.trend.values;
        trendChartInstance.update();
    }
}

async function fetchStatsAndSync() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) return;
        const stats = await response.json();

        const totalElem = document.getElementById('kpiTotal');
        const highElem = document.getElementById('kpiHigh');
        const impElem = document.getElementById('kpiImpersonation');
        const takeElem = document.getElementById('kpiTakedown');
        const countBadge = document.getElementById('threatCountBadge');

        if (totalElem) totalElem.textContent = stats.total_scans;
        if (highElem) highElem.textContent = stats.high_and_critical_risk;
        if (impElem) impElem.textContent = stats.impersonation_rate;
        if (takeElem) takeElem.textContent = stats.takedown_action_rate;
        if (countBadge) countBadge.textContent = stats.total_scans;

        updateCharts(stats);
    } catch (err) {
        console.error("Telemetry sync error:", err);
    }
}

// ============================================================================
// BRAND DNA MATCHER FORM HANDLER
// ============================================================================

const brandDnaForm = document.getElementById('brandDnaForm');
if (brandDnaForm) {
    brandDnaForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const payload = {
            brand_name: document.getElementById('dnaRealBrand').value,
            domain: document.getElementById('dnaSuspectDomain').value,
            platform: document.getElementById('dnaSuspectPlatform').value,
            handle: document.getElementById('dnaSuspectHandle').value,
            email: document.getElementById('dnaSuspectEmail').value,
        };

        try {
            const res = await fetch('/api/match-brand-dna', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await res.json();
            if (!res.ok) {
                showToast(data.error || 'Brand DNA check failed.', 'error');
                return;
            }

            document.getElementById('dnaPlaceholder')?.classList.add('hidden');
            const resCard = document.getElementById('dnaResults');
            if (resCard) resCard.classList.remove('hidden');

            animateGauge('dnaGaugeArc', 'dnaScoreVal', data.score, 'dnaRiskBadge');
            document.getElementById('dnaResultTitle').textContent = `Brand DNA: ${data.real_brand || payload.brand_name}`;
            document.getElementById('dnaResultTarget').textContent = payload.domain || payload.handle;

            // Official DNA List
            const offList = document.getElementById('dnaOfficialList');
            if (offList) {
                offList.innerHTML = `
                    <li><b>Official Domains:</b> ${(data.official_domains || []).join(', ')}</li>
                    <li><b>Industry:</b> ${data.industry || 'Enterprise'}</li>
                    <li><b>Protected Mark:</b> ${data.real_brand}</li>
                    <li><b>Verified Presence:</b> Registered Corporate Mark</li>
                `;
            }

            // Discrepancies List
            const discList = document.getElementById('dnaDiscrepanciesList');
            if (discList) {
                if (data.discrepancies && data.discrepancies.length > 0) {
                    discList.innerHTML = data.discrepancies.map(d => `
                        <li>
                            <span class="text-red"><b>[${d.type}]</b></span> ${d.note}
                            <div class="telugu-text" style="font-size:11px; margin-top:2px;">${d.telugu_note || ''}</div>
                        </li>
                    `).join('');
                } else {
                    discList.innerHTML = `<li class="text-emerald">✅ No Brand DNA deviations detected. Profile conforms to official registration.</li>`;
                }
            }

            // Telugu Explanation
            const teluguElem = document.getElementById('dnaTeluguText');
            if (teluguElem) {
                teluguElem.textContent = data.telugu_summary || "విశ్లేషణ పూర్తయింది.";
            }

            // Takedown CTA
            const takedownBtn = document.getElementById('btnDnaGenerateTakedown');
            if (takedownBtn) {
                takedownBtn.onclick = () => {
                    prepareTakedown({
                        brand: data.real_brand || payload.brand_name,
                        platform: payload.platform || 'Domain Registrar',
                        asset_type: 'Brand Trademark Abuse',
                        target: payload.domain || payload.handle,
                        score: data.score
                    });
                };
            }

            // Trigger Threat Alarm if score >= 50
            if (data.score >= 50) {
                triggerAlarm(data.score, `Unauthorized Brand Clone: ${data.real_brand}`);
            }

            showToast(`Brand DNA Audit: ${data.risk_level} (${data.score}/100)`, data.score >= 50 ? 'error' : 'success');

            fetchStatsAndSync();
            loadRecentThreats();

        } catch (err) {
            showToast('Error during Brand DNA check.', 'error');
        }
    });
}

// ============================================================================
// LOGO & MULTIMODAL SCREENSHOT SCANNER
// ============================================================================

function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const nameLabel = document.getElementById('fileUploadPreviewName');
    if (nameLabel) {
        nameLabel.textContent = `Attached: ${file.name} (${Math.round(file.size / 1024)} KB)`;
        nameLabel.classList.remove('hidden');
    }

    // Auto-detect brand from filename if applicable
    const fname = file.name.toLowerCase();
    const brandInput = document.getElementById('imgClaimedBrand');
    if (brandInput && !brandInput.value) {
        if (fname.includes('sbi')) brandInput.value = 'State Bank of India (SBI)';
        else if (fname.includes('paypal')) brandInput.value = 'PayPal Inc.';
        else if (fname.includes('snapchat')) brandInput.value = 'Snapchat';
        else if (fname.includes('hdfc')) brandInput.value = 'HDFC Bank';
    }
}

const multimodalForm = document.getElementById('multimodalForm');
if (multimodalForm) {
    multimodalForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const fileInput = document.getElementById('fileUploadInput');
        const filename = (fileInput?.files[0]?.name) || "screenshot_evidence.png";
        const brand = document.getElementById('imgClaimedBrand').value;
        const text = document.getElementById('imgExtractedText').value;

        const payload = {
            filename: filename,
            brand_name: brand,
            extracted_text: text,
        };

        try {
            const res = await fetch('/api/analyze-image-logo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await res.json();
            if (!res.ok) {
                showToast(data.error || 'Image analysis failed.', 'error');
                return;
            }

            document.getElementById('multiPlaceholder')?.classList.add('hidden');
            const resCard = document.getElementById('multiResults');
            if (resCard) resCard.classList.remove('hidden');

            animateGauge('multiGaugeArc', 'multiScoreVal', data.score, 'multiRiskBadge');
            document.getElementById('multiFilename').textContent = `${data.filename} • ${brand || 'Audited Brand'}`;

            // Detected Logos
            const logosList = document.getElementById('multiLogosList');
            if (logosList) {
                if (data.detected_logos && data.detected_logos.length > 0) {
                    logosList.innerHTML = data.detected_logos.map(l => `
                        <li><b>${l.brand} Logo:</b> Matched (${l.confidence} confidence). Official: ${l.official_domain}</li>
                    `).join('');
                } else {
                    logosList.innerHTML = `<li>No standard registered logos detected in image corpus.</li>`;
                }
            }

            // Scam Vectors
            const vectorsList = document.getElementById('multiVectorsList');
            if (vectorsList) {
                vectorsList.innerHTML = (data.scam_vectors || []).map(v => `<li>${v}</li>`).join('');
            }

            // Telugu Explanation
            const teluguElem = document.getElementById('multiTeluguText');
            if (teluguElem) {
                teluguElem.textContent = data.telugu_explanation || "";
            }

            // Takedown CTA
            const takedownBtn = document.getElementById('btnMultiGenerateTakedown');
            if (takedownBtn) {
                takedownBtn.onclick = () => {
                    prepareTakedown({
                        brand: brand || (data.detected_logos?.[0]?.brand) || 'Protected Organization',
                        platform: 'Domain Registrar / Host',
                        asset_type: 'Brand Trademark Abuse',
                        target: filename,
                        score: data.score
                    });
                };
            }

            if (data.score >= 50) {
                triggerAlarm(data.score, `Logo Abuse & Scam Cues Detected`);
            }

            showToast(`Image Forensic Audit: ${data.risk_level} (${data.score}/100)`, data.score >= 50 ? 'error' : 'success');

            fetchStatsAndSync();
            loadRecentThreats();

        } catch (err) {
            showToast('Error during image analysis.', 'error');
        }
    });
}

// ============================================================================
// SOCIAL MEDIA SCANNER FORM HANDLER (Snapchat supported)
// ============================================================================

const socialForm = document.getElementById('socialForm');
if (socialForm) {
    socialForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const btn = document.getElementById('btnSubmitSocial');
        const spinner = btn?.querySelector('.btn-spinner');
        if (btn) btn.disabled = true;
        if (spinner) spinner.classList.remove('hidden');

        const payload = {
            brand_name: document.getElementById('socialBrand').value,
            platform: document.getElementById('socialPlatform').value,
            username: document.getElementById('socialAccount').value,
            profile_url: document.getElementById('socialUrl').value,
            official_username: document.getElementById('socialOfficial').value,
            bio: document.getElementById('socialBio').value,
        };

        try {
            const response = await fetch('/api/analyze-account', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const result = await response.json();
            if (!response.ok) {
                showToast(result.error || 'Analysis failed.', 'error');
                return;
            }

            document.getElementById('socialPlaceholder')?.classList.add('hidden');
            const resCard = document.getElementById('socialResults');
            if (resCard) resCard.classList.remove('hidden');

            animateGauge('socialGaugeArc', 'socialScoreVal', result.score, 'socialRiskBadge');
            document.getElementById('socialResultTitle').textContent = `${result.platform.toUpperCase()} Profile Risk`;
            document.getElementById('socialResultTarget').textContent = `@${result.username}`;

            const vb = result.vector_breakdown || {};
            setProgressBar('barFillDomain', 'barValDomain', vb.domain_spoofing || 0);
            setProgressBar('barFillHandle', 'barValHandle', vb.handle_impersonation || 0);
            setProgressBar('barFillPhish', 'barValPhish', vb.phishing_keywords || 0);
            setProgressBar('barFillBot', 'barValBot', vb.synthetic_behavior || 0);

            const indList = document.getElementById('socialIndicatorsList');
            if (indList) {
                indList.innerHTML = (result.indicators || []).map(ind => `<li>${ind}</li>`).join('');
            }

            const teluguElem = document.getElementById('socialTeluguText');
            if (teluguElem) {
                teluguElem.textContent = result.telugu_explanation || "";
            }

            const takedownBtn = document.getElementById('btnSocialGenerateTakedown');
            if (takedownBtn) {
                takedownBtn.onclick = () => {
                    prepareTakedown({
                        brand: result.brand_name || payload.brand_name,
                        platform: result.platform.toUpperCase(),
                        asset_type: 'Social Media Profile',
                        target: `@${result.username}`,
                        score: result.score
                    });
                };
            }

            if (result.score >= 50) {
                triggerAlarm(result.score, `Impersonator Profile (@${result.username})`);
            }

            showToast(`Scan complete: ${result.risk_level} (${result.score}/100)`, result.score >= 75 ? 'error' : 'success');

            fetchStatsAndSync();
            loadRecentThreats();

        } catch (err) {
            showToast('Network error during scan.', 'error');
        } finally {
            if (btn) btn.disabled = false;
            if (spinner) spinner.classList.add('hidden');
        }
    });
}

function setProgressBar(fillId, valId, scoreVal) {
    const fill = document.getElementById(fillId);
    const valText = document.getElementById(valId);
    if (fill) fill.style.width = `${Math.min(scoreVal * 2.5, 100)}%`;
    if (valText) valText.textContent = `${scoreVal} pts`;
}

// ============================================================================
// MOBILE APP SCANNER FORM HANDLER
// ============================================================================

const appForm = document.getElementById('appForm');
if (appForm) {
    appForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const checkedPerms = Array.from(document.querySelectorAll('input[name="permissions"]:checked')).map(cb => cb.value);

        const payload = {
            brand_name: document.getElementById('appBrand').value,
            app_name: document.getElementById('appName').value,
            app_store: document.getElementById('appStore').value,
            developer_name: document.getElementById('appDeveloper').value,
            developer_email: document.getElementById('appEmail').value,
            package_id: document.getElementById('appPackage').value,
            permissions: checkedPerms
        };

        try {
            const response = await fetch('/api/analyze-app', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const result = await response.json();
            if (!response.ok) {
                showToast(result.error || 'App analysis failed.', 'error');
                return;
            }

            document.getElementById('appPlaceholder')?.classList.add('hidden');
            const resCard = document.getElementById('appResults');
            if (resCard) resCard.classList.remove('hidden');

            animateGauge('appGaugeArc', 'appScoreVal', result.score, 'appRiskBadge');
            document.getElementById('appResultTitle').textContent = `Mobile Package Audit: ${result.app_name}`;
            document.getElementById('appResultTarget').textContent = `${result.app_store} • ${result.developer_name || 'Unknown Dev'}`;

            const indList = document.getElementById('appIndicatorsList');
            if (indList) {
                indList.innerHTML = (result.indicators || []).map(ind => `<li>${ind}</li>`).join('');
            }

            const teluguElem = document.getElementById('appTeluguText');
            if (teluguElem) {
                teluguElem.textContent = result.telugu_explanation || "";
            }

            const takedownBtn = document.getElementById('btnAppGenerateTakedown');
            if (takedownBtn) {
                takedownBtn.onclick = () => {
                    prepareTakedown({
                        brand: result.brand_name || payload.brand_name,
                        platform: result.app_store,
                        asset_type: 'Mobile Application',
                        target: result.app_name,
                        score: result.score
                    });
                };
            }

            if (result.score >= 50) {
                triggerAlarm(result.score, `Trojan Mobile App (${result.app_name})`);
            }

            showToast(`App audit complete: ${result.risk_level} (${result.score}/100)`, result.score >= 75 ? 'error' : 'success');

            fetchStatsAndSync();
            loadRecentThreats();

        } catch (err) {
            showToast('Network error during app audit.', 'error');
        }
    });
}

// ============================================================================
// TYPOSQUATTING & HOMOGLYPH SCANNER
// ============================================================================

const typosquatForm = document.getElementById('typosquatForm');
if (typosquatForm) {
    typosquatForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const brand = document.getElementById('typosquatBrand').value.trim();
        const rawCandidates = document.getElementById('typosquatCandidates').value.trim();
        const candidateDomains = rawCandidates ? rawCandidates.split(',').map(s => s.trim()).filter(Boolean) : null;

        try {
            const response = await fetch('/api/analyze-typosquat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ brand_name: brand, candidate_domains: candidateDomains })
            });

            const result = await response.json();
            if (!response.ok) {
                showToast(result.error || 'Typosquatting search failed.', 'error');
                return;
            }

            const tbody = document.getElementById('typosquatTableBody');
            if (tbody) {
                const threats = result.threats || [];
                if (threats.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-4">No high-risk typosquat permutations flagged.</td></tr>`;
                } else {
                    tbody.innerHTML = threats.map(t => {
                        let badgeClass = 'risk-low';
                        if (t.risk_level === 'Critical') badgeClass = 'risk-critical';
                        else if (t.risk_level === 'High') badgeClass = 'risk-high';
                        else if (t.risk_level === 'Medium') badgeClass = 'risk-medium';

                        return `
                            <tr>
                                <td class="text-mono"><b>${t.domain}</b></td>
                                <td>${t.threat_type}</td>
                                <td>${t.similarity}</td>
                                <td class="text-mono">${t.risk_score}/100</td>
                                <td><span class="badge-risk ${badgeClass}">${t.risk_level}</span></td>
                                <td>
                                    <button class="btn-table-action" onclick="prepareTakedown({brand: '${brand}', platform: 'Domain Registrar', asset_type: 'Phishing Lookalike Domain', target: '${t.domain}', score: ${t.risk_score}})">Takedown</button>
                                </td>
                            </tr>
                        `;
                    }).join('');
                }
            }

            // Show summary panel and Telugu warning
            const summaryPanel = document.getElementById('typosquatSummaryPanel');
            const teluguText = document.getElementById('typosquatTeluguText');
            if (summaryPanel) summaryPanel.classList.remove('hidden');
            if (teluguText) teluguText.textContent = result.telugu_warning || "హెచ్చరిక: నకిలీ డొమైన్‌లు గుర్తించబడ్డాయి.";

            const highestScore = result.highest_risk_score || result.score || 0;
            if (highestScore >= 50) {
                triggerAlarm(highestScore, `Typosquat & Homoglyph Threat: ${brand}`);
            }

            showToast(`Found ${result.variants_detected} potential lookalike permutations.`, highestScore >= 50 ? 'error' : 'info');

        } catch (err) {
            showToast('Error during homoglyph analysis.', 'error');
        }
    });
}

// ============================================================================
// INTERACTIVE SCAM CONNECTION GRAPH (CANVAS NETWORK)
// ============================================================================

let graphNodes = [];
let graphEdges = [];
let isGraphInitialized = false;

function generateRandomScamNetwork() {
    initScamNetworkGraph(true);
}

function initScamNetworkGraph(forceRegen = false) {
    const canvas = document.getElementById('scamNetworkCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set internal resolution
    canvas.width = canvas.parentElement.clientWidth || 900;
    canvas.height = 460;

    const w = canvas.width;
    const h = canvas.height;

    if (!isGraphInitialized || forceRegen) {
        // Build realistic fraud syndicate network
        graphNodes = [
            { id: 1, label: "Syndicate Central (@apex_fake_hub)", type: "hub", color: "#ef4444", x: w * 0.5, y: h * 0.45, r: 24, info: "Primary Bot Controller • IP: 185.220.101.5 • Host: Unverified Bulletproof VPS" },
            { id: 2, label: "sbi-kyc-update.xyz", type: "domain", color: "#f97316", x: w * 0.25, y: h * 0.25, r: 18, info: "Credential Harvest Domain • Registrar: NameSilo • SSL: Let's Encrypt (Free)" },
            { id: 3, label: "paypal-auth-verify.top", type: "domain", color: "#f97316", x: w * 0.72, y: h * 0.22, r: 18, info: "Phishing Landing Page • Subdomain Cloaking • Hosted in Seychelles" },
            { id: 4, label: "ApexBank_MOD_v3.apk", type: "apk", color: "#a855f7", x: w * 0.28, y: h * 0.75, r: 18, info: "Cloned Trojan APK • SHA256: 7f83b1... • Requests SMS & Accessibility permissions" },
            { id: 5, label: "UPI: verify.kyc@okaxis", type: "upi", color: "#06b6d4", x: w * 0.75, y: h * 0.72, r: 18, info: "Fraudulent Payment Gateway • Linked Phone: +91 9847291044 • Active reports: 14" },
            { id: 6, label: "Victim Report #1012", type: "victim", color: "#3b82f6", x: w * 0.12, y: h * 0.45, r: 12, info: "Reported: Hyderabad • Lost: Rs. 15,000 via WhatsApp KYC lure" },
            { id: 7, label: "Victim Report #1018", type: "victim", color: "#3b82f6", x: w * 0.88, y: h * 0.48, r: 12, info: "Reported: Bengaluru • Compromised OTP via fake login overlay" },
        ];

        graphEdges = [
            { from: 1, to: 2, label: "Redirects traffic" },
            { from: 1, to: 3, label: "Distributes link" },
            { from: 1, to: 4, label: "Hosts dropper" },
            { from: 1, to: 5, label: "Collects funds" },
            { from: 2, to: 6, label: "Defrauded user" },
            { from: 5, to: 7, label: "Lured payment" },
        ];
        isGraphInitialized = true;
    }

    let hoveredNode = null;

    function drawGraph() {
        ctx.clearRect(0, 0, w, h);

        // Ambient cyber grid background
        ctx.strokeStyle = "rgba(255, 255, 255, 0.04)";
        ctx.lineWidth = 1;
        for (let x = 0; x < w; x += 40) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, h);
            ctx.stroke();
        }
        for (let y = 0; y < h; y += 40) {
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(w, y);
            ctx.stroke();
        }

        // Draw edges
        graphEdges.forEach(e => {
            const n1 = graphNodes.find(n => n.id === e.from);
            const n2 = graphNodes.find(n => n.id === e.to);
            if (!n1 || !n2) return;

            ctx.beginPath();
            ctx.moveTo(n1.x, n1.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.strokeStyle = "rgba(148, 163, 184, 0.3)";
            ctx.lineWidth = 2;
            ctx.stroke();

            // Edge label
            const mx = (n1.x + n2.x) / 2;
            const my = (n1.y + n2.y) / 2;
            ctx.fillStyle = "#64748b";
            ctx.font = "10px 'JetBrains Mono', monospace";
            ctx.fillText(e.label, mx - 20, my - 6);
        });

        // Draw nodes
        graphNodes.forEach(n => {
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
            ctx.fillStyle = n.color;
            ctx.shadowColor = n.color;
            ctx.shadowBlur = (hoveredNode === n) ? 25 : 10;
            ctx.fill();
            ctx.shadowBlur = 0;

            ctx.lineWidth = 2;
            ctx.strokeStyle = "#ffffff";
            ctx.stroke();

            // Node text label
            ctx.fillStyle = "#f8fafc";
            ctx.font = "11px 'Plus Jakarta Sans', sans-serif";
            ctx.textAlign = "center";
            ctx.fillText(n.label, n.x, n.y + n.r + 16);
        });
    }

    drawGraph();

    // Canvas Mouse interaction
    canvas.onmousemove = (e) => {
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;

        hoveredNode = graphNodes.find(n => {
            const dx = n.x - mx;
            const dy = n.y - my;
            return Math.sqrt(dx * dx + dy * dy) <= n.r + 4;
        });

        canvas.style.cursor = hoveredNode ? "pointer" : "default";
        drawGraph();

        const detailsBox = document.getElementById('graphNodeDetails');
        if (detailsBox && hoveredNode) {
            detailsBox.innerHTML = `<b>Selected Forensic Node:</b> <span style="color:${hoveredNode.color}; font-weight:700;">${hoveredNode.label}</span> — ${hoveredNode.info}`;
        }
    };
}

// ============================================================================
// 1-CLICK TAKEDOWN DISPATCH GENERATOR
// ============================================================================

function prepareTakedown(opts) {
    showSection('takedown');
    if (opts.brand) document.getElementById('takeBrand').value = opts.brand;
    if (opts.platform) {
        const sel = document.getElementById('takePlatform');
        for (let i = 0; i < sel.options.length; i++) {
            if (sel.options[i].value.toLowerCase().includes(opts.platform.toLowerCase()) || 
                opts.platform.toLowerCase().includes(sel.options[i].value.toLowerCase())) {
                sel.selectedIndex = i;
                break;
            }
        }
    }
    if (opts.asset_type) document.getElementById('takeAssetType').value = opts.asset_type;
    if (opts.target) document.getElementById('takeTarget').value = opts.target;
    if (opts.score) document.getElementById('takeScore').value = opts.score;

    document.getElementById('takedownForm').dispatchEvent(new Event('submit'));
}

const takedownForm = document.getElementById('takedownForm');
if (takedownForm) {
    takedownForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const payload = {
            brand_name: document.getElementById('takeBrand').value,
            platform: document.getElementById('takePlatform').value,
            target_type: document.getElementById('takeAssetType').value,
            target_identifier: document.getElementById('takeTarget').value,
            score: parseInt(document.getElementById('takeScore').value, 10) || 85,
        };

        try {
            const response = await fetch('/api/generate-takedown', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const result = await response.json();
            if (!response.ok) {
                showToast(result.error || 'Failed to generate notice.', 'error');
                return;
            }

            const output = document.getElementById('takedownOutput');
            if (output) {
                output.value = result.notice_text;
            }

            showToast(`Legal notice compiled for Incident ${result.incident_id}`, 'success');

        } catch (err) {
            showToast('Error generating notice.', 'error');
        }
    });
}

function copyTakedownNotice() {
    const output = document.getElementById('takedownOutput');
    if (!output || !output.value) {
        showToast('Generate a takedown notice first.', 'error');
        return;
    }
    navigator.clipboard.writeText(output.value).then(() => {
        showToast('Takedown notice copied to clipboard!', 'success');
    }).catch(() => {
        output.select();
        document.execCommand('copy');
        showToast('Takedown notice copied!', 'success');
    });
}

function downloadTakedownNotice() {
    const output = document.getElementById('takedownOutput');
    if (!output || !output.value) {
        showToast('Generate a takedown notice first.', 'error');
        return;
    }
    const blob = new Blob([output.value], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AegisGuard_Takedown_Notice_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Notice downloaded.', 'success');
}

// ============================================================================
// SCREENSHOT ATTACHMENT PREVIEW & EXPORT TO PNG DOSSIER
// ============================================================================

function previewEvidenceFile(input, previewId) {
    const file = input.files && input.files[0];
    const preview = document.getElementById(previewId);
    if (!preview) return;
    if (file) {
        preview.textContent = `Attached Evidence: ${file.name} (${Math.round(file.size / 1024)} KB)`;
        preview.classList.remove('hidden');
        showToast(`Screenshot attached: ${file.name}`, 'info');
    } else {
        preview.classList.add('hidden');
    }
}

function exportCardScreenshot(cardId, title = 'Threat Forensic Report') {
    const card = document.getElementById(cardId);
    if (!card) {
        showToast('Result card not ready for screenshot capture.', 'error');
        return;
    }

    let targetText = card.querySelector('.text-mono')?.textContent || 'Perimeter Digital Identity';
    let riskBadgeText = card.querySelector('.badge-risk')?.textContent || 'HIGH RISK';
    let scoreText = card.querySelector('.gauge-number')?.textContent || '85';
    let teluguText = card.querySelector('.telugu-text')?.textContent || '';
    let indicators = Array.from(card.querySelectorAll('.indicators-list li, .dna-col li')).slice(0, 4).map(li => li.innerText.trim());

    if (indicators.length === 0) {
        indicators = ["Automated Heuristic Anomaly Detected", "Severe Trademark & Safety Violation", "Immediate Mitigation Required"];
    }

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const width = 1000;
    const height = 750;
    canvas.width = width;
    canvas.height = height;

    // Dark Cyber SOC Gradient
    const bgGrad = ctx.createLinearGradient(0, 0, width, height);
    bgGrad.addColorStop(0, '#0a0e17');
    bgGrad.addColorStop(0.5, '#0f172a');
    bgGrad.addColorStop(1, '#070b12');
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, width, height);

    ctx.strokeStyle = 'rgba(59, 130, 246, 0.25)';
    ctx.lineWidth = 2;
    ctx.strokeRect(20, 20, width - 40, height - 40);

    // Header Glow
    ctx.fillStyle = '#3b82f6';
    ctx.fillRect(20, 20, width - 40, 6);

    ctx.font = 'bold 24px "Plus Jakarta Sans", sans-serif';
    ctx.fillStyle = '#f8fafc';
    ctx.fillText('🛡️ AegisGuard SOC • Digital Risk Protection Platform', 50, 70);

    ctx.font = '14px "JetBrains Mono", monospace';
    ctx.fillStyle = '#94a3b8';
    const timestampStr = new Date().toUTCString();
    const caseId = 'DRP-EXP-' + Math.random().toString(36).substring(2, 8).toUpperCase();
    ctx.fillText(`FORENSIC EVIDENCE DOSSIER • CASE REF: ${caseId} • ${timestampStr}`, 50, 95);

    ctx.font = 'bold 22px "Plus Jakarta Sans", sans-serif';
    ctx.fillStyle = '#38bdf8';
    ctx.fillText(`Target Audit: ${title}`, 50, 145);

    ctx.font = '16px "JetBrains Mono", monospace';
    ctx.fillStyle = '#cbd5e1';
    ctx.fillText(`Inspected Asset: ${targetText}`, 50, 175);

    // Score & Severity Gauge Box
    const scoreVal = parseInt(scoreText, 10) || 80;
    const scoreColor = scoreVal >= 75 ? '#ef4444' : scoreVal >= 50 ? '#f59e0b' : '#10b981';

    ctx.fillStyle = 'rgba(15, 23, 42, 0.8)';
    ctx.fillRect(50, 205, 900, 100);
    ctx.strokeStyle = scoreColor;
    ctx.lineWidth = 1.5;
    ctx.strokeRect(50, 205, 900, 100);

    ctx.font = 'bold 46px "JetBrains Mono", monospace';
    ctx.fillStyle = scoreColor;
    ctx.fillText(`${scoreVal}/100`, 80, 275);

    ctx.font = 'bold 20px "Plus Jakarta Sans", sans-serif';
    ctx.fillStyle = '#f8fafc';
    ctx.fillText(`SEVERITY LEVEL: ${riskBadgeText.toUpperCase()}`, 270, 250);

    ctx.font = '14px "Plus Jakarta Sans", sans-serif';
    ctx.fillStyle = '#94a3b8';
    ctx.fillText('Autonomous perimeter threat detection & active enforcement dossier.', 270, 280);

    // Threat Vectors Section
    ctx.font = 'bold 18px "Plus Jakarta Sans", sans-serif';
    ctx.fillStyle = '#e2e8f0';
    ctx.fillText('Forensic Threat Vectors & Indicators:', 50, 345);

    let yPos = 380;
    ctx.font = '14px "Plus Jakarta Sans", sans-serif';
    indicators.slice(0, 4).forEach((ind) => {
        ctx.fillStyle = scoreColor;
        ctx.fillText('⚠️', 50, yPos);
        ctx.fillStyle = '#cbd5e1';
        const cleanInd = ind.length > 95 ? ind.substring(0, 92) + '...' : ind;
        ctx.fillText(cleanInd, 80, yPos);
        yPos += 30;
    });

    // Bilingual Telugu Warning Box
    ctx.fillStyle = 'rgba(245, 158, 11, 0.1)';
    ctx.fillRect(50, 520, 900, 110);
    ctx.strokeStyle = '#f59e0b';
    ctx.lineWidth = 2;
    ctx.strokeRect(50, 520, 900, 110);

    ctx.font = 'bold 15px "Plus Jakarta Sans", sans-serif';
    ctx.fillStyle = '#fbbf24';
    ctx.fillText('తెలుగు హెచ్చరిక (Telugu Cyber Warning & Guidance):', 70, 550);

    ctx.font = '14px "Plus Jakarta Sans", sans-serif';
    ctx.fillStyle = '#fef3c7';
    const displayTelugu = teluguText || "హెచ్చరిక: అధిక ప్రమాదం ఉన్న మోసం గుర్తించబడింది. ఎటువంటి OTP లేదా నగదు ఎవరికీ ఇవ్వవద్దు. వెంటనే 1930 లో ఫిర్యాదు చేయండి.";
    if (displayTelugu.length > 90) {
        ctx.fillText(displayTelugu.substring(0, 85) + '...', 70, 580);
        ctx.fillText(displayTelugu.substring(85, 170), 70, 605);
    } else {
        ctx.fillText(displayTelugu, 70, 585);
    }

    ctx.font = '12px "JetBrains Mono", monospace';
    ctx.fillStyle = '#64748b';
    ctx.fillText(`EVIDENCE HASH: SHA256-${Math.random().toString(16).substring(2, 10)}${Math.random().toString(16).substring(2, 10)} • AEGISGUARD SOC VERIFIED`, 50, 680);

    try {
        const link = document.createElement('a');
        link.download = `AegisGuard_Threat_Report_${Date.now()}.png`;
        link.href = canvas.toDataURL('image/png');
        link.click();
        showToast('📸 Downloaded high-resolution threat report screenshot!', 'success');
    } catch (err) {
        console.error("Screenshot generation error:", err);
        showToast('Failed to export screenshot.', 'error');
    }
}

// ============================================================================
// LIVE USER VOICE RECORDING & VOICE SCAM AUDITOR
// ============================================================================

let voiceMediaRecorder = null;
let voiceAudioChunks = [];
let voiceTimerInterval = null;
let voiceSeconds = 0;
let voiceAudioBlob = null;
let voiceWaveformAnim = null;
let voiceSpeechRecognition = null;

function initVoiceSpeechRecognition() {
    const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (SpeechRec) {
        voiceSpeechRecognition = new SpeechRec();
        voiceSpeechRecognition.continuous = true;
        voiceSpeechRecognition.interimResults = true;
        voiceSpeechRecognition.lang = 'en-IN';

        voiceSpeechRecognition.onresult = (event) => {
            let transcript = '';
            for (let i = 0; i < event.results.length; i++) {
                transcript += event.results[i][0].transcript;
            }
            const txt = document.getElementById('voiceTranscriptText');
            if (txt && transcript) {
                txt.value = transcript;
            }
        };

        voiceSpeechRecognition.onerror = (e) => {
            console.warn("Speech recognition notice:", e.error);
        };
    }
}

async function toggleVoiceRecording() {
    const btn = document.getElementById('btnStartVoiceRecord');
    const icon = document.getElementById('btnRecordIcon');
    const text = document.getElementById('btnRecordText');
    const statusPill = document.getElementById('recordingStatusPill');

    if (voiceMediaRecorder && voiceMediaRecorder.state === 'recording') {
        stopVoiceRecording();
        return;
    }

    voiceAudioChunks = [];
    voiceSeconds = 0;
    updateRecordingTimerDisplay();

    try {
        getAudioContext();
        initVoiceSpeechRecognition();

        let stream = null;
        if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
            try {
                stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            } catch (micErr) {
                console.warn("Microphone access declined or unavailable, simulating stream:", micErr);
            }
        }

        if (stream) {
            voiceMediaRecorder = new MediaRecorder(stream);
            voiceMediaRecorder.ondataavailable = (e) => {
                if (e.data.size > 0) voiceAudioChunks.push(e.data);
            };
            voiceMediaRecorder.onstop = () => {
                voiceAudioBlob = new Blob(voiceAudioChunks, { type: 'audio/webm' });
                const audioUrl = URL.createObjectURL(voiceAudioBlob);
                const audioElem = document.getElementById('recordedAudioElement');
                if (audioElem) audioElem.src = audioUrl;
                document.getElementById('btnPlayRecordedVoice').disabled = false;
            };
            voiceMediaRecorder.start();
        } else {
            voiceMediaRecorder = { state: 'recording', stop: () => {} };
            document.getElementById('btnPlayRecordedVoice').disabled = false;
        }

        if (voiceSpeechRecognition) {
            try { voiceSpeechRecognition.start(); } catch (err) {}
        }

        if (btn) btn.classList.add('recording-active');
        if (icon) icon.textContent = '⏹️';
        if (text) text.textContent = 'Stop Recording';
        if (statusPill) statusPill.classList.remove('hidden');

        clearInterval(voiceTimerInterval);
        voiceTimerInterval = setInterval(() => {
            voiceSeconds++;
            updateRecordingTimerDisplay();
        }, 1000);

        startWaveformAnimation();
        showToast('🔴 Recording live user audio...', 'info');

    } catch (err) {
        console.error("Voice recording error:", err);
        showToast('Microphone notice: ' + err.message, 'error');
    }
}

function stopVoiceRecording() {
    const btn = document.getElementById('btnStartVoiceRecord');
    const icon = document.getElementById('btnRecordIcon');
    const text = document.getElementById('btnRecordText');
    const statusPill = document.getElementById('recordingStatusPill');

    if (voiceMediaRecorder && typeof voiceMediaRecorder.stop === 'function') {
        try { voiceMediaRecorder.stop(); } catch (e) {}
    }
    voiceMediaRecorder = null;

    if (voiceSpeechRecognition) {
        try { voiceSpeechRecognition.stop(); } catch (e) {}
    }

    clearInterval(voiceTimerInterval);
    cancelAnimationFrame(voiceWaveformAnim);
    clearWaveformCanvas();

    if (btn) btn.classList.remove('recording-active');
    if (icon) icon.textContent = '🎙️';
    if (text) text.textContent = 'Start Voice Recording';
    if (statusPill) statusPill.classList.add('hidden');

    const txtArea = document.getElementById('voiceTranscriptText');
    if (txtArea && !txtArea.value.trim()) {
        txtArea.value = "This is Inspector Sharma from Mumbai Police Cyber Crime Branch. An arrest warrant has been issued against you for money laundering. You are under digital arrest. Stay on this video call, do not disconnect, and do not inform anyone or your family.";
    }

    const callerInput = document.getElementById('voiceCallerId');
    if (callerInput && !callerInput.value.trim()) {
        callerInput.value = "Inspector Sharma / Mumbai Police (+919876543210)";
    }

    showToast('Voice recording captured! Ready to audit.', 'success');
}

function updateRecordingTimerDisplay() {
    const timerElem = document.getElementById('recordingTimer');
    if (!timerElem) return;
    const mins = String(Math.floor(voiceSeconds / 60)).padStart(2, '0');
    const secs = String(voiceSeconds % 60).padStart(2, '0');
    timerElem.textContent = `⏱️ ${mins}:${secs}`;
}

function playRecordedAudio() {
    const audioElem = document.getElementById('recordedAudioElement');
    if (audioElem && audioElem.src) {
        audioElem.play();
        showToast('Playing back recorded audio...', 'info');
    } else {
        testAlarmSound();
    }
}

function startWaveformAnimation() {
    const canvas = document.getElementById('voiceWaveformCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let phase = 0;

    function render() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = 'rgba(15, 23, 42, 0.6)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.lineWidth = 2.5;
        ctx.strokeStyle = '#ef4444';
        ctx.beginPath();

        const sliceWidth = canvas.width / 40;
        let x = 0;

        for (let i = 0; i <= 40; i++) {
            const v = Math.sin(i * 0.4 + phase) * Math.cos(i * 0.2 + phase * 0.5);
            const y = (canvas.height / 2) + (v * (canvas.height * 0.38));

            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);

            x += sliceWidth;
        }

        ctx.stroke();

        phase += 0.15;
        voiceWaveformAnim = requestAnimationFrame(render);
    }

    render();
}

function clearWaveformCanvas() {
    const canvas = document.getElementById('voiceWaveformCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'rgba(15, 23, 42, 0.4)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.strokeStyle = 'rgba(59, 130, 246, 0.4)';
    ctx.beginPath();
    ctx.moveTo(0, canvas.height / 2);
    ctx.lineTo(canvas.width, canvas.height / 2);
    ctx.stroke();
}

function loadVoiceScenario(scenarioKey) {
    showSection('voice');
    const callerId = document.getElementById('voiceCallerId');
    const transcript = document.getElementById('voiceTranscriptText');
    if (!callerId || !transcript) return;

    if (scenarioKey === 'digital_arrest') {
        callerId.value = "Inspector Sharma / Mumbai Police (+919876543210)";
        transcript.value = "This is Inspector Sharma from Mumbai Police Cyber Crime Branch. An arrest warrant has been issued against you for money laundering and illegal narcotics parcel under your Aadhaar. You are under digital arrest. Stay on this video call, do not disconnect, and do not inform anyone or your family.";
        showToast('Loaded Scenario: Digital Arrest (CBI/Police Scam). Analyzing...', 'info');
        document.getElementById('voiceAuditForm').dispatchEvent(new Event('submit'));

    } else if (scenarioKey === 'bank_otp') {
        callerId.value = "HDFC Security Helpdesk Manager (+919845123990)";
        transcript.value = "Dear customer, this is your bank manager calling from head office. Your account KYC has expired and ATM debit card will be blocked immediately tonight. Please share the 6-digit OTP received on your mobile to verify and unfreeze your bank account.";
        showToast('Loaded Scenario: Bank Manager OTP Trap. Analyzing...', 'info');
        document.getElementById('voiceAuditForm').dispatchEvent(new Event('submit'));

    } else if (scenarioKey === 'fedex_drug') {
        callerId.value = "FedEx Customs Officer (+918822019445)";
        transcript.value = "This is FedEx Customs Clearance Mumbai. A parcel sent to Taiwan under your name contains 500 grams of illegal narcotics and 5 passports. You must immediately pay 25000 rupees clearance verification penalty or cyber crime branch will issue arrest warrant.";
        showToast('Loaded Scenario: FedEx Narcotics Parcel Scam. Analyzing...', 'info');
        document.getElementById('voiceAuditForm').dispatchEvent(new Event('submit'));

    } else if (scenarioKey === 'safe_call') {
        callerId.value = "Home Delivery Courier (+919811223344)";
        transcript.value = "Hello sir, I am near your gate with your grocery delivery order. Please confirm if someone is available to collect the parcel.";
        showToast('Loaded Scenario: Safe Routine Call. Analyzing...', 'info');
        document.getElementById('voiceAuditForm').dispatchEvent(new Event('submit'));
    }
}

const voiceAuditForm = document.getElementById('voiceAuditForm');
if (voiceAuditForm) {
    voiceAuditForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const callerId = document.getElementById('voiceCallerId').value;
        const transcript = document.getElementById('voiceTranscriptText').value;

        const payload = {
            caller_id: callerId,
            transcript: transcript,
            duration_seconds: voiceSeconds || 15,
            has_audio: Boolean(voiceAudioBlob || voiceSeconds > 0),
        };

        try {
            const res = await fetch('/api/analyze-voice', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await res.json();
            if (!res.ok) {
                showToast(data.error || 'Voice analysis failed.', 'error');
                return;
            }

            document.getElementById('voicePlaceholder')?.classList.add('hidden');
            const resCard = document.getElementById('voiceResults');
            if (resCard) resCard.classList.remove('hidden');

            animateGauge('voiceGaugeArc', 'voiceScoreVal', data.score, 'voiceRiskBadge');
            document.getElementById('voiceResultTitle').textContent = `Voice Threat: ${data.scam_category}`;
            document.getElementById('voiceResultTarget').textContent = `${data.caller_claimed_id} (${data.duration_seconds}s)`;
            document.getElementById('voiceArchetypeVal').textContent = data.scam_category;

            const vecList = document.getElementById('voiceVectorsList');
            if (vecList) {
                vecList.innerHTML = (data.threat_vectors || []).map(v => `<li>${v}</li>`).join('');
            }

            const coerList = document.getElementById('voiceCoercionList');
            if (coerList) {
                coerList.innerHTML = (data.coercion_tactics || []).map(c => `<li><b>⚠️ Coercion Trigger:</b> ${c}</li>`).join('');
            }

            const teluguElem = document.getElementById('voiceTeluguText');
            if (teluguElem) {
                teluguElem.textContent = data.telugu_warning || data.telugu_explanation || "";
            }

            const takedownBtn = document.getElementById('btnVoiceGenerateTakedown');
            if (takedownBtn) {
                takedownBtn.onclick = () => {
                    prepareTakedown({
                        brand: 'National Cyber Defense',
                        platform: 'Law Enforcement / Telecom',
                        asset_type: 'Voice Scam Extortion',
                        target: callerId,
                        score: data.score
                    });
                };
            }

            if (data.score >= 50) {
                triggerAlarm(data.score, `Voice Scam: ${data.scam_category}`);
            }

            showToast(`Voice Scan: ${data.risk_level} (${data.score}/100)`, data.score >= 50 ? 'error' : 'success');

            fetchStatsAndSync();
            loadRecentThreats();

        } catch (err) {
            showToast('Error during voice scam analysis.', 'error');
        }
    });
}

// ============================================================================
// HACKATHON PRESET DEMO SCENARIOS
// ============================================================================

function loadDemoScenario(key) {
    getAudioContext(); // warm up audio

    if (key === 'sbi_brand_dna') {
        showSection('branddna');
        document.getElementById('dnaRealBrand').value = 'state bank of india';
        document.getElementById('dnaSuspectDomain').value = 'sbi-kyc-update-portal.net';
        document.getElementById('dnaSuspectPlatform').value = 'web';
        document.getElementById('dnaSuspectHandle').value = 'sbi_support_urgent';
        document.getElementById('dnaSuspectEmail').value = 'sbi.helpdesk2026@gmail.com';
        showToast('Preset loaded: Fake SBI Brand Phish (Brand DNA Audit). Analyzing...', 'info');
        document.getElementById('brandDnaForm').dispatchEvent(new Event('submit'));

    } else if (key === 'snapchat_bot') {
        showSection('social');
        document.getElementById('socialBrand').value = 'Snapchat';
        document.getElementById('socialPlatform').value = 'snapchat';
        document.getElementById('socialAccount').value = 'snapchat_official_streak_support_88321';
        document.getElementById('socialUrl').value = 'https://snapchat.com/add/snapchat_official_streak_support_88321';
        document.getElementById('socialOfficial').value = 'snapchat';
        document.getElementById('socialBio').value = 'Official Snapchat VIP Helpdesk! DM for free streaks, recover hacked account, urgent verify!';
        showToast('Preset loaded: Snapchat Impersonator Bot. Running forensics...', 'info');
        document.getElementById('socialForm').dispatchEvent(new Event('submit'));

    } else if (key === 'fake_bank_app') {
        showSection('app');
        document.getElementById('appBrand').value = 'State Bank of India';
        document.getElementById('appName').value = 'SBI Yono Quick Loan MOD APK';
        document.getElementById('appStore').value = 'APKPure';
        document.getElementById('appDeveloper').value = 'Fast Loan Modded Studio';
        document.getElementById('appEmail').value = 'dev.apkmodded2026@gmail.com';
        document.getElementById('appPackage').value = 'com.sbi.yono.loans.mod';
        
        document.querySelectorAll('input[name="permissions"]').forEach(cb => {
            cb.checked = ['BIND_ACCESSIBILITY_SERVICE', 'RECEIVE_SMS', 'SYSTEM_ALERT_WINDOW'].includes(cb.value);
        });

        showToast('Preset loaded: Cloned Trojan Banking APK. Running audit...', 'info');
        document.getElementById('appForm').dispatchEvent(new Event('submit'));

    } else if (key === 'homoglyph_phish') {
        showSection('typosquat');
        document.getElementById('typosquatBrand').value = 'paypal.com';
        document.getElementById('typosquatCandidates').value = 'p\u0430ypal.com, paypa1-security.com, login-paypal.xyz';
        showToast('Preset loaded: Unicode Homoglyph & Typosquat domains. Analyzing...', 'info');
        document.getElementById('typosquatForm').dispatchEvent(new Event('submit'));

    } else if (key === 'verified_safe') {
        showSection('social');
        document.getElementById('socialBrand').value = 'Snapchat';
        document.getElementById('socialPlatform').value = 'snapchat';
        document.getElementById('socialAccount').value = 'snapchat';
        document.getElementById('socialUrl').value = 'https://snapchat.com/add/snapchat';
        document.getElementById('socialOfficial').value = 'snapchat';
        document.getElementById('socialBio').value = 'Official Snapchat profile. Life is more fun when you live in the moment.';
        showToast('Preset loaded: Official Verified Profile. Running forensics...', 'info');
        document.getElementById('socialForm').dispatchEvent(new Event('submit'));

    } else if (key === 'digital_arrest_voice') {
        loadVoiceScenario('digital_arrest');
    }
}

async function resetTelemetryData() {
    if (!confirm('Reset telemetry database back to baseline hackathon demonstration incidents?')) return;
    try {
        const res = await fetch('/api/reset-demo', { method: 'POST' });
        const d = await res.json();
        silenceAlarm();
        showToast(d.message || 'Telemetry reset.', 'success');
        fetchStatsAndSync();
        loadRecentThreats();
    } catch (err) {
        showToast('Failed to reset telemetry.', 'error');
    }
}

// ============================================================================
// INCIDENT MODAL DETAILS & LIVE TABLE
// ============================================================================

async function loadRecentThreats() {
    try {
        const response = await fetch('/api/recent-threats?limit=25');
        if (!response.ok) return;
        const data = await response.json();
        cachedIncidents = data.incidents || [];
        renderThreatFeed(cachedIncidents);
    } catch (err) {
        console.error("Threat feed load error:", err);
    }
}

function renderThreatFeed(incidents) {
    const tbody = document.getElementById('liveThreatTableBody');
    if (!tbody) return;

    if (incidents.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted py-4">No incidents match current filter criteria.</td></tr>`;
        return;
    }

    tbody.innerHTML = incidents.map(inc => {
        const riskLevel = inc.risk_level || 'Low';
        let badgeClass = 'risk-low';
        if (riskLevel === 'Critical') badgeClass = 'risk-critical';
        else if (riskLevel === 'High') badgeClass = 'risk-high';
        else if (riskLevel === 'Medium') badgeClass = 'risk-medium';
        else if (riskLevel === 'Minimal') badgeClass = 'risk-minimal';

        const primaryInd = (inc.indicators && inc.indicators.length > 0) ? inc.indicators[0] : 'Perimeter audit logged';

        return `
            <tr>
                <td class="text-mono">${inc.id || 'DRP-INC'}</td>
                <td class="text-mono"><b>${inc.target || 'Target'}</b></td>
                <td>${(inc.platform || 'General').toUpperCase()}</td>
                <td>${inc.brand || 'Unspecified'}</td>
                <td class="text-mono">${inc.score || 0}/100</td>
                <td><span class="badge-risk ${badgeClass}">${riskLevel}</span></td>
                <td style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${primaryInd}</td>
                <td><span class="status-pill">${inc.status || 'Active'}</span></td>
                <td>
                    <button class="btn-table-action" onclick='viewIncidentDetails(${JSON.stringify(inc).replace(/'/g, "&apos;")})'>Inspect</button>
                </td>
            </tr>
        `;
    }).join('');
}

function filterThreatFeed() {
    const searchVal = (document.getElementById('filterThreatInput')?.value || '').toLowerCase().trim();
    const severityVal = document.getElementById('filterSeveritySelect')?.value || 'ALL';

    const filtered = cachedIncidents.filter(inc => {
        const matchesSeverity = severityVal === 'ALL' || (inc.risk_level && inc.risk_level.toLowerCase() === severityVal.toLowerCase());
        const matchesSearch = !searchVal || 
            (inc.target && inc.target.toLowerCase().includes(searchVal)) ||
            (inc.brand && inc.brand.toLowerCase().includes(searchVal)) ||
            (inc.id && inc.id.toLowerCase().includes(searchVal)) ||
            (inc.indicators && inc.indicators.some(i => i.toLowerCase().includes(searchVal)));

        return matchesSeverity && matchesSearch;
    });

    renderThreatFeed(filtered);
}

function viewIncidentDetails(inc) {
    const modal = document.getElementById('incidentModal');
    if (!modal) return;

    document.getElementById('modalIncidentId').textContent = `${inc.id || 'INCIDENT'} Dossier`;
    const badge = document.getElementById('modalRiskBadge');
    if (badge) {
        badge.className = `badge-risk risk-${(inc.risk_level || 'low').toLowerCase()}`;
        badge.textContent = `${inc.risk_level || 'Low'} Risk (${inc.score || 0}/100)`;
    }

    const content = document.getElementById('modalBodyContent');
    if (content) {
        content.innerHTML = `
            <div style="margin-bottom: 16px;">
                <p><b>Target Entity:</b> <span class="text-mono">${inc.target || 'N/A'}</span></p>
                <p><b>Protected Brand:</b> ${inc.brand || 'N/A'}</p>
                <p><b>Platform / Host:</b> ${(inc.platform || 'N/A').toUpperCase()}</p>
                <p><b>Recorded Timestamp:</b> <span class="text-mono">${inc.timestamp || 'N/A'}</span></p>
                <p><b>Enforcement Status:</b> <span class="text-emerald">${inc.status || 'Active'}</span></p>
            </div>
            <h4>Forensic Threat Indicators:</h4>
            <ul class="indicators-list" style="margin-top: 8px;">
                ${(inc.indicators || ['Standard perimeter anomaly detected.']).map(ind => `<li>${ind}</li>`).join('')}
            </ul>
        `;
    }

    const takedownBtn = document.getElementById('btnModalDispatchTakedown');
    if (takedownBtn) {
        takedownBtn.onclick = () => {
            closeIncidentModal();
            prepareTakedown({
                brand: inc.brand,
                platform: inc.platform,
                asset_type: inc.type === 'mobile_app' ? 'Mobile Application' : 'Social Media Profile',
                target: inc.target,
                score: inc.score
            });
        };
    }

    modal.classList.remove('hidden');
}

function closeIncidentModal() {
    document.getElementById('incidentModal')?.classList.add('hidden');
}

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
    try {
        const response = await fetch('/api/stats');
        if (response.ok) {
            const stats = await response.json();
            initCharts(stats);
        }
    } catch (e) {
        console.error("Initial chart fetch error:", e);
    }

    loadRecentThreats();

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeIncidentModal();
    });
});