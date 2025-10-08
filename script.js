document.addEventListener('DOMContentLoaded', () => {
    const API_BASE_URL = "http://127.0.0.1:5555";

    // --- View Navigation ---
    const navButtons = document.querySelectorAll('.nav-btn');
    const views = document.querySelectorAll('.view');

    // Get specific view elements
    const dashboardView = document.getElementById('dashboard-view');
    const phishingView = document.getElementById('phishing-view');
    const scriptView = document.getElementById('script-view');
    const cveView = document.getElementById('cve-view');
    const logView = document.getElementById('log-view-tool');
    const dgaView = document.getElementById('dga-view');
    const soarView = document.getElementById('soar-view');
    const intelView = document.getElementById('intel-view');
    const settingsView = document.getElementById('settings-view');

    navButtons.forEach(button => {
        button.addEventListener('click', () => {
            const viewId = button.dataset.view;
            showView(viewId);
        });
    });

    function showView(viewName) {
        // Hide all views
        views.forEach(v => v.classList.remove('active'));
        // Deactivate all nav buttons
        navButtons.forEach(b => b.classList.remove('active'));

        // Activate the selected view and button
        const targetView = document.getElementById(viewName);
        const targetButton = document.querySelector(`[data-view="${viewName}"]`);

        if (targetView && targetButton) {
            targetView.classList.add('active');
            targetButton.classList.add('active');

            // Special actions for specific views
            if (viewName === 'settings-view') {
                updateSettingsView();
            }
        }
    }

    // --- Dashboard: System Status ---
    const systemStatusContainer = document.getElementById('system-status-container');
    const statusIndicator = document.getElementById('status-indicator');
    const enginesIndicator = document.getElementById('engines-indicator');
    const blockedIndicator = document.getElementById('blocked-indicator');
    const alertsView = document.getElementById('alerts-view');

    function updateStatusIndicator(state, text) { // state: 'connected', 'disconnected', 'connecting'
        statusIndicator.className = state;
        statusIndicator.querySelector('span').textContent = `Status: ${text}`;
    }

    // --- API Fetch Utility ---
    async function fetchAPI(endpoint, options = {}) {
        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
            if (!response.ok && response.status !== 503) { // Allow 503 for disabled tools
                const errorData = await response.json().catch(() => ({ message: response.statusText }));
                throw new Error(`API Error: ${response.status} - ${errorData.message || response.statusText}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`Failed to fetch from ${endpoint}:`, error);
            updateStatusIndicator('disconnected', 'Disconnected');
            throw error;
        }
    }
    
    // --- Dashboard: Alerts ---
    async function updateAlerts() {
        try {
            const data = await fetchAPI('/api/alerts');
            alertsView.innerHTML = ''; // Clear list
            if (data.alerts && data.alerts.length === 0) {
                alertsView.innerHTML = '<p>No recent security alerts.</p>';
            } else if (data.alerts) {
                data.alerts.forEach(alert => {
                    const alertDiv = document.createElement('div');
                    alertDiv.className = 'alert-item';
                    const timestamp = new Date(alert.timestamp).toLocaleString();
                    alertDiv.innerHTML = `
                        <strong>${alert.alert_type}</strong> from <strong>${alert.source_ip}</strong> at ${timestamp}<br>
                        Details: ${alert.details}
                    `;
                    alertsView.appendChild(alertDiv);
                });
            } else {
                alertsView.innerHTML = '<p>Error loading alerts.</p>';
            }
        } catch (error) {
            alertsView.innerHTML = `<p>Error loading alerts: ${error.message}</p>`;
        }
    }

    // --- Dashboard: System Status Panel ---
    function renderToolStatus(toolStatuses) {
        systemStatusContainer.innerHTML = '';
        for (const [tool, status] of Object.entries(toolStatuses)) {
            systemStatusContainer.innerHTML += `<p><strong>${tool}:</strong> <span class="${status.includes('Loaded') ? 'status-loaded' : 'status-disabled'}">${status}</span></p>`;
        }
    }

    async function updateStatus() {
        try {
            const data = await fetchAPI('/api/status');
            updateStatusIndicator('connected', data.status || 'Running');
            enginesIndicator.querySelector('span').textContent = data.active_engines.join(', ') || 'None';
            blockedIndicator.querySelector('span').textContent = data.currently_blocked ?? 'N/A';
            renderToolStatus(data.tool_statuses);
        } catch (error) {
            // Error is handled in fetchAPI
        }
    }

    // --- Dashboard: Blocked IPs ---
    const blockedList = document.getElementById('blocked-ips-list');
    const unblockBtn = document.getElementById('unblock-btn');
    let selectedIp = null;

    blockedList.addEventListener('click', (e) => {
        if (e.target && e.target.tagName === 'LI') {
            // Clear previous selection
            document.querySelectorAll('#blocked-ips-list li').forEach(li => li.classList.remove('selected'));
            // Add new selection
            e.target.classList.add('selected');
            selectedIp = e.target.dataset.ip;
            unblockBtn.disabled = !selectedIp;
        }
    });

    unblockBtn.addEventListener('click', async () => {
        if (!selectedIp) return;
        if (confirm(`Are you sure you want to unblock ${selectedIp}?`)) {
            try {
                await fetchAPI('/api/unblock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: selectedIp })
                });
                // Refresh list after unblocking
                updateBlockedIps();
            } catch (error) {
                alert(`Failed to unblock IP: ${error.message}`);
            }
        }
    });

    async function updateBlockedIps() {
        try {
            const data = await fetchAPI('/api/blocked_ips');
            blockedList.innerHTML = ''; // Clear list
            if (data.length === 0) {
                blockedList.innerHTML = '<li>No IPs are currently blocked.</li>';
            } else {
                data.sort((a, b) => a.expiry_time - b.expiry_time).forEach(item => {
                    const li = document.createElement('li');
                    const timeLeft = Math.max(0, Math.round(item.expiry_time - Date.now() / 1000));
                    li.textContent = `${item.ip.padEnd(16)} | Expires in: ${String(timeLeft).padStart(4, ' ')}s | Rule: ${item.rule_name}`;
                    li.dataset.ip = item.ip;
                    blockedList.appendChild(li);
                });
            }
            selectedIp = null;
            unblockBtn.disabled = true;
        } catch (error) {
            blockedList.innerHTML = '<li>Error loading blocked IPs.</li>';
        }
    }

    // --- Dashboard: Live Event Log ---
    const logViewPre = document.getElementById('log-view'); // This is the pre tag for the live log
    async function updateLogs() {
        try {
            const data = await fetchAPI('/api/log');
            logViewPre.textContent = data.log_events.join('');
            logViewPre.scrollTop = logViewPre.scrollHeight; // Auto-scroll
        } catch (error) {
            // Don't clear logs on error, just fail silently
        }
    }

    // --- Script Analyzer (Static & ML) ---
    const scriptInput = document.getElementById('script-input');
    const reportOutput = document.getElementById('analysis-report');
    const analyzeStaticBtn = document.getElementById('analyze-static-btn');
    const analyzeMlBtn = document.getElementById('analyze-ml-btn');

    async function handleScriptAnalysis(analysisType) {
        const code = scriptInput.value;
        if (!code.trim()) {
            alert('Please paste some code to analyze.');
            return;
        }

        reportOutput.textContent = 'Analyzing...';
        analyzeStaticBtn.disabled = true;
        analyzeMlBtn.disabled = true;
        try {
            const data = await fetchAPI('/api/analyze_script', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: code, analysis_type: analysisType })
            });
            reportOutput.textContent = data.report;
        } catch (error) {
            reportOutput.textContent = `Error during analysis: ${error.message}`;
        } finally {
            analyzeStaticBtn.disabled = false;
            analyzeMlBtn.disabled = false;
        }
    }
    analyzeStaticBtn.addEventListener('click', () => handleScriptAnalysis('static'));
    analyzeMlBtn.addEventListener('click', () => handleScriptAnalysis('ml'));

    // --- CVE Classifier ---
    const cveInput = document.getElementById('cve-input');
    const cveClassifyBtn = document.getElementById('cve-classify-btn');
    const cveResults = document.getElementById('cve-results');

    cveClassifyBtn.addEventListener('click', async () => {
        const description = cveInput.value;
        if (!description.trim()) {
            alert('Please paste a CVE description to classify.');
            return;
        }
        cveResults.innerHTML = 'Classifying...';
        cveClassifyBtn.disabled = true;
        try {
            const data = await fetchAPI('/api/classify_cve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ description })
            });
            
            if (data.results && data.results.length > 0) {
                cveResults.innerHTML = ''; // Clear 'Classifying...'
                data.results.forEach(result => {
                    const item = document.createElement('div');
                    item.className = 'cve-result-item';
                    
                    const confidence = result.confidence.toFixed(2);
                    
                    item.innerHTML = `
                        <div class="cve-category">${result.category}</div>
                        <div class="confidence-bar-container">
                            <div class="confidence-bar" style="width: ${confidence}%;">${confidence}%</div>
                        </div>
                    `;
                    cveResults.appendChild(item);
                });
            } else {
                cveResults.textContent = 'Could not determine vulnerability type.';
            }
        } catch (error) {
            cveResults.textContent = `Error during classification: ${error.message}`;
        } finally {
            cveClassifyBtn.disabled = false;
        }
    });

    // --- Phishing Detector ---
    const phishingInput = document.getElementById('phishing-input');
    const phishingCheckBtn = document.getElementById('phishing-check-btn');
    const phishingResults = document.getElementById('phishing-results');

    phishingCheckBtn.addEventListener('click', async () => {
        const url = phishingInput.value;
        if (!url.trim()) {
            alert('Please enter a URL to check.');
            return;
        }
        phishingResults.innerHTML = 'Checking URL...';
        phishingCheckBtn.disabled = true;
        try {
            const data = await fetchAPI('/api/detect_phishing', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            if (data.error) {
                phishingResults.innerHTML = `<p class="error-message">${data.error}</p>`;
            } else {
                phishingResults.innerHTML = `
                    <p><strong>Prediction:</strong> ${data.label}</p>
                    <p><strong>Confidence:</strong> ${data.confidence.toFixed(2)}%</p>
                `;
            }
        } catch (error) {
            phishingResults.innerHTML = `<p class="error-message">Error: ${error.message}</p>`;
        } finally {
            phishingCheckBtn.disabled = false;
        }
    });

    // --- Log Anomaly Detector ---
    const logInput = document.getElementById('log-input');
    const logAnalyzeBtn = document.getElementById('log-analyze-btn');
    const logResults = document.getElementById('log-results');

    logAnalyzeBtn.addEventListener('click', async () => {
        const logEntry = logInput.value;
        if (!logEntry.trim()) {
            alert('Please enter a log entry to analyze.');
            return;
        }
        logResults.innerHTML = 'Analyzing log entry...';
        logAnalyzeBtn.disabled = true;
        try {
            const data = await fetchAPI('/api/analyze_log', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ log_entry: logEntry })
            });
            if (data.error) {
                logResults.innerHTML = `<p class="error-message">${data.error}</p>`;
            } else {
                logResults.innerHTML = `<p><strong>Prediction:</strong> ${data.prediction}</p>`;
            }
        } catch (error) {
            logResults.innerHTML = `<p class="error-message">Error: ${error.message}</p>`;
        } finally {
            logAnalyzeBtn.disabled = false;
        }
    });

    // --- DGA Detector ---
    const dgaInput = document.getElementById('dga-input');
    const dgaAnalyzeBtn = document.getElementById('dga-analyze-btn');
    const dgaResults = document.getElementById('dga-results');

    dgaAnalyzeBtn.addEventListener('click', async () => {
        const domain = dgaInput.value;
        if (!domain.trim()) {
            alert('Please enter a domain name to analyze.');
            return;
        }
        dgaResults.innerHTML = 'Analyzing domain...';
        dgaAnalyzeBtn.disabled = true;
        try {
            const data = await fetchAPI('/api/detect_dga', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: domain })
            });
            if (data.error) {
                dgaResults.innerHTML = `<p class="error-message">${data.error}</p>`;
            } else {
                dgaResults.innerHTML = `
                    <p><strong>Prediction:</strong> ${data.prediction}</p>
                    <p><strong>Confidence:</strong> ${data.confidence.toFixed(2)}%</p>
                `;
            }
        } catch (error) {
            dgaResults.innerHTML = `<p class="error-message">Error: ${error.message}</p>`;
        } finally {
            dgaAnalyzeBtn.disabled = false;
        }
    });

    // --- SOAR Triage Bot ---
    const soarAlertSource = document.getElementById('soar-alert-source');
    const soarSeverity = document.getElementById('soar-severity');
    const soarConfidence = document.getElementById('soar-confidence');
    const soarEntityType = document.getElementById('soar-entity-type');
    const soarTriageBtn = document.getElementById('soar-triage-btn');
    const soarResults = document.getElementById('soar-results');

    soarTriageBtn.addEventListener('click', async () => {
        const alertData = {
            alert_source: soarAlertSource.value,
            severity: soarSeverity.value,
            confidence: parseInt(soarConfidence.value),
            entity_type: soarEntityType.value
        };
        soarResults.innerHTML = 'Getting recommendation...';
        soarTriageBtn.disabled = true;
        try {
            const data = await fetchAPI('/api/decide_playbook', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(alertData)
            });
            if (data.error) {
                soarResults.innerHTML = `<p class="error-message">${data.error}</p>`;
            } else {
                soarResults.innerHTML = `<p><strong>Recommended Action:</strong> ${data.recommended_action}</p>`;
            }
        } catch (error) {
            soarResults.innerHTML = `<p class="error-message">Error: ${error.message}</p>`;
        } finally {
            soarTriageBtn.disabled = false;
        }
    });

    // --- Threat Intel Summarizer ---
    const intelInput = document.getElementById('intel-input');
    const intelSummarizeBtn = document.getElementById('intel-summarize-btn');
    const intelResults = document.getElementById('intel-results');
    const showdownConverter = new showdown.Converter(); // For markdown rendering

    intelSummarizeBtn.addEventListener('click', async () => {
        const reportText = intelInput.value;
        if (!reportText.trim()) {
            alert('Please paste a threat report to summarize.');
            return;
        }
        intelResults.innerHTML = 'Generating summary...';
        intelSummarizeBtn.disabled = true;
        try {
            const data = await fetchAPI('/api/summarize_report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ report_text: reportText })
            });
            if (data.error) {
                intelResults.innerHTML = `<p class="error-message">${data.error}</p>`;
            } else {
                intelResults.innerHTML = showdownConverter.makeHtml(data.summary);
            }
        } catch (error) {
            intelResults.innerHTML = `<p class="error-message">Error: ${error.message}</p>`;
        } finally {
            intelSummarizeBtn.disabled = false;
        }
    });

    // --- Settings View ---
    const engineSettingsContainer = document.getElementById('engine-settings-container');
    const settingBlockDuration = document.getElementById('setting-block-duration');
    const settingWhitelistIps = document.getElementById('setting-whitelist-ips');
    const saveSettingsBtn = document.getElementById('save-settings-btn');

    async function updateSettingsView() {
        try {
            const config = await fetchAPI('/api/config');
            engineSettingsContainer.innerHTML = ''; // Clear previous toggles

            // Dynamically create toggles for each engine/tool
            for (const section in config) {
                if (section === 'Settings') {
                    // Handle general settings separately
                    settingBlockDuration.value = config[section].block_duration;
                    settingWhitelistIps.value = config[section].whitelist_ips;
                } else {
                    // Create toggle for other sections (engines/tools)
                    const enabled = config[section].enabled === 'true';
                    const div = document.createElement('div');
                    div.className = 'form-group';
                    div.innerHTML = `
                        <label>${section}</label>
                        <label class="toggle-switch">
                            <input type="checkbox" data-section="${section}" data-key="enabled" ${enabled ? 'checked' : ''}>
                            <span class="slider round"></span>
                        </label>
                    `;
                    engineSettingsContainer.appendChild(div);
                }
            }
        } catch (error) {
            engineSettingsContainer.innerHTML = `<p class="error-message">Error loading settings: ${error.message}</p>`;
        }
    }

    saveSettingsBtn.addEventListener('click', async () => {
        const newConfig = {};

        // Collect engine/tool settings
        document.querySelectorAll('#engine-settings-container input[type="checkbox"]').forEach(checkbox => {
            const section = checkbox.dataset.section;
            const key = checkbox.dataset.key;
            if (!newConfig[section]) newConfig[section] = {};
            newConfig[section][key] = checkbox.checked ? 'true' : 'false';
        });

        // Collect general settings
        newConfig['Settings'] = {
            block_duration: settingBlockDuration.value,
            whitelist_ips: settingWhitelistIps.value
        };

        saveSettingsBtn.disabled = true;
        try {
            const response = await fetchAPI('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newConfig)
            });
            if (response.error) {
                alert(`Failed to save settings: ${response.error}`);
            } else {
                alert('Settings saved and applied successfully!');
                updateStatus(); // Refresh dashboard status after saving settings
            }
        } catch (error) {
            alert(`Error saving settings: ${error.message}`);
        } finally {
            saveSettingsBtn.disabled = false;
        }
    });

    // --- Auto-Refresh Loop ---
    function refreshAllData() {
        updateStatus();
        updateBlockedIps();
        updateLogs();
        updateAlerts(); // Refresh alerts on dashboard
    }

    // Initial load
    showView('dashboard-view');
    refreshAllData();

    // Set up auto-refresh every 3 seconds
    setInterval(refreshAllData, 3000);
});