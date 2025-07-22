// AI Threat Detection System Frontend
class ThreatDetectionUI {
    constructor() {
        // Use relative paths for Vercel deployment
        this.apiUrl = window.location.origin;
        this.refreshInterval = 30000; // 30 seconds
        this.autoRefresh = true;
        this.maxLogs = 100;
        this.charts = {};
        this.refreshTimer = null;
        
        this.init();
    }

    init() {
        this.loadSettings();
        this.setupEventListeners();
        this.initializeCharts();
        this.startAutoRefresh();
        this.loadDashboard();
    }

    loadSettings() {
        const settings = JSON.parse(localStorage.getItem('threatDetectionSettings') || '{}');
        this.apiUrl = settings.apiUrl || this.apiUrl;
        this.refreshInterval = settings.refreshInterval || this.refreshInterval;
        this.autoRefresh = settings.autoRefresh !== undefined ? settings.autoRefresh : this.autoRefresh;
        this.maxLogs = settings.maxLogs || this.maxLogs;
    }

    saveSettings() {
        const settings = {
            apiUrl: this.apiUrl,
            refreshInterval: this.refreshInterval,
            autoRefresh: this.autoRefresh,
            maxLogs: this.maxLogs
        };
        localStorage.setItem('threatDetectionSettings', JSON.stringify(settings));
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.menu-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                this.showSection(item.dataset.section);
            });
        });

        // Threat Detection Form
        document.getElementById('threatDetectionForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.analyzeThreats();
        });

        // Settings Form
        document.getElementById('settingsForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveSettings();
            this.showToast('Settings saved successfully!', 'success');
        });

        // Alert Filters
        document.getElementById('alertSeverityFilter').addEventListener('change', () => {
            this.loadAlerts();
        });

        // Log Filters
        document.getElementById('logSeverityFilter').addEventListener('change', () => {
            this.loadThreatLogs();
        });

        document.getElementById('logSearch').addEventListener('input', (e) => {
            this.filterThreatLogs(e.target.value);
        });
    }

    showSection(sectionId) {
        // Hide all sections
        document.querySelectorAll('.section').forEach(section => {
            section.classList.remove('active');
        });

        // Remove active class from menu items
        document.querySelectorAll('.menu-item').forEach(item => {
            item.classList.remove('active');
        });

        // Show selected section
        document.getElementById(sectionId).classList.add('active');
        document.querySelector(`[data-section="${sectionId}"]`).classList.add('active');

        // Load section data
        switch(sectionId) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'analytics':
                this.loadAnalytics();
                break;
            case 'alerts':
                this.loadAlerts();
                break;
            case 'logs':
                this.loadThreatLogs();
                break;
            case 'settings':
                this.loadSettings();
                break;
        }
    }

    async loadDashboard() {
        try {
            this.showLoading();
            
            // Load system stats
            const stats = await this.apiCall('/api/stats');
            this.updateDashboardStats(stats);

            // Load system health
            const analytics = await this.apiCall('/api/analytics');
            this.updateSystemHealth(analytics);

            // Load recent threats
            const threats = await this.apiCall('/api/threats?limit=5');
            this.updateThreatFeed(threats.threats || []);

            this.hideLoading();
        } catch (error) {
            this.hideLoading();
            this.showToast('Failed to load dashboard data', 'error');
            console.error('Dashboard load error:', error);
        }
    }

    updateDashboardStats(stats) {
        document.getElementById('totalThreats').textContent = stats.threats?.total || 0;
        document.getElementById('activeAlerts').textContent = stats.alerts?.total || 0;
        document.getElementById('threatsToday').textContent = stats.threats?.total || 0;
        document.getElementById('avgResponse').textContent = '0ms'; // Placeholder
    }

    updateSystemHealth(analytics) {
        const healthChecks = analytics.system_health?.checks || {};
        const healthGrid = document.getElementById('systemHealth');
        
        Object.entries(healthChecks).forEach(([key, check]) => {
            const healthItem = healthGrid.querySelector(`[data-health="${key}"]`);
            if (healthItem) {
                const statusSpan = healthItem.querySelector('.health-status');
                statusSpan.textContent = check.status;
                statusSpan.className = `health-status ${check.status}`;
            }
        });
    }

    updateThreatFeed(threats) {
        const feed = document.getElementById('threatFeed');
        
        if (threats.length === 0) {
            feed.innerHTML = `
                <div class="feed-item">
                    <div class="feed-icon">
                        <i class="fas fa-info-circle"></i>
                    </div>
                    <div class="feed-content">
                        <p>No recent threats detected</p>
                        <span class="feed-time">Just now</span>
                    </div>
                </div>
            `;
            return;
        }

        feed.innerHTML = threats.map(threat => `
            <div class="feed-item">
                <div class="feed-icon">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="feed-content">
                    <p>${threat.description}</p>
                    <span class="feed-time">${this.formatTime(threat.timestamp)}</span>
                </div>
            </div>
        `).join('');
    }

    async analyzeThreats() {
        const formData = {
            source_ip: document.getElementById('sourceIp').value,
            dest_ip: document.getElementById('destIp').value,
            port: parseInt(document.getElementById('port').value),
            protocol: document.getElementById('protocol').value,
            user_agent: document.getElementById('userAgent').value,
            url: document.getElementById('url').value,
            message: document.getElementById('message').value
        };

        try {
            this.showLoading();
            
            const response = await this.apiCall('/api/detect', {
                method: 'POST',
                body: JSON.stringify(formData)
            });

            this.displayResults(response);
            this.showToast(`Analysis complete: ${response.threats_detected} threats detected`, 'success');
            
            // Refresh dashboard
            setTimeout(() => this.loadDashboard(), 1000);
            
        } catch (error) {
            this.hideLoading();
            this.showToast('Failed to analyze threats', 'error');
            console.error('Analysis error:', error);
        }
    }

    displayResults(response) {
        const resultsCard = document.getElementById('resultsCard');
        const resultsContainer = document.getElementById('detectionResults');
        const resultsBadge = document.getElementById('resultsBadge');

        resultsBadge.textContent = `${response.threats_detected} Threats`;
        resultsCard.style.display = 'block';

        if (response.threats_detected === 0) {
            resultsContainer.innerHTML = `
                <div class="threat-item low">
                    <div class="threat-header">
                        <span class="threat-type">No Threats Detected</span>
                        <span class="threat-severity low">Safe</span>
                    </div>
                    <div class="threat-description">
                        The analyzed traffic appears to be normal and safe.
                    </div>
                    <div class="threat-meta">
                        <span>Confidence: 100%</span>
                        <span>Method: Pattern Analysis</span>
                    </div>
                </div>
            `;
            return;
        }

        resultsContainer.innerHTML = response.threats.map(threat => `
            <div class="threat-item ${threat.severity}">
                <div class="threat-header">
                    <span class="threat-type">${threat.type}</span>
                    <span class="threat-severity ${threat.severity}">${threat.severity}</span>
                </div>
                <div class="threat-description">${threat.description}</div>
                <div class="threat-meta">
                    <span>Confidence: ${Math.round(threat.confidence * 100)}%</span>
                    <span>Method: ${threat.detection_method}</span>
                    <span>Source: ${threat.source_ip || 'Unknown'}</span>
                </div>
            </div>
        `).join('');
    }

    async loadAnalytics() {
        try {
            const analytics = await this.apiCall('/api/analytics');
            this.updateAnalyticsCharts(analytics);
            this.updateRealTimeMetrics(analytics);
        } catch (error) {
            this.showToast('Failed to load analytics', 'error');
            console.error('Analytics load error:', error);
        }
    }

    updateAnalyticsCharts(analytics) {
        const threatData = analytics.threat_analytics || {};
        
        // Update threat distribution chart
        if (this.charts.threatChart) {
            this.charts.threatChart.destroy();
        }
        
        const threatCtx = document.getElementById('threatChart').getContext('2d');
        this.charts.threatChart = new Chart(threatCtx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(threatData.threats_by_type || {}),
                datasets: [{
                    data: Object.values(threatData.threats_by_type || {}),
                    backgroundColor: [
                        '#667eea',
                        '#764ba2',
                        '#f093fb',
                        '#f5576c',
                        '#4facfe'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Update severity chart
        if (this.charts.severityChart) {
            this.charts.severityChart.destroy();
        }
        
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        this.charts.severityChart = new Chart(severityCtx, {
            type: 'bar',
            data: {
                labels: Object.keys(threatData.threats_by_severity || {}),
                datasets: [{
                    label: 'Threats by Severity',
                    data: Object.values(threatData.threats_by_severity || {}),
                    backgroundColor: [
                        '#10b981',
                        '#f59e0b',
                        '#ef4444',
                        '#dc2626'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    updateRealTimeMetrics(analytics) {
        const metrics = analytics.real_time_metrics || {};
        
        document.getElementById('threatsPerMinute').textContent = metrics.threats_per_minute || 0;
        document.getElementById('requestsPerMinute').textContent = metrics.requests_per_minute || 0;
        document.getElementById('avgConfidence').textContent = `${Math.round((analytics.threat_analytics?.avg_confidence || 0) * 100)}%`;
        document.getElementById('systemUptime').textContent = '100%';
    }

    async loadAlerts() {
        try {
            const severityFilter = document.getElementById('alertSeverityFilter').value;
            const url = severityFilter ? `/api/alerts?severity=${severityFilter}` : '/api/alerts';
            const alerts = await this.apiCall(url);
            this.displayAlerts(alerts);
        } catch (error) {
            this.showToast('Failed to load alerts', 'error');
            console.error('Alerts load error:', error);
        }
    }

    displayAlerts(alerts) {
        const alertsList = document.getElementById('alertsList');
        
        if (alerts.length === 0) {
            alertsList.innerHTML = `
                <div class="alert-item low">
                    <div class="alert-header">
                        <span class="alert-title">No Alerts</span>
                        <span class="alert-time">Just now</span>
                    </div>
                    <div class="alert-description">
                        No alerts have been generated recently.
                    </div>
                </div>
            `;
            return;
        }

        alertsList.innerHTML = alerts.map(alert => `
            <div class="alert-item ${alert.severity || 'low'}">
                <div class="alert-header">
                    <span class="alert-title">${alert.type || 'Alert'}</span>
                    <span class="alert-time">${this.formatTime(alert.timestamp)}</span>
                </div>
                <div class="alert-description">${alert.description || 'No description'}</div>
                <span class="alert-severity ${alert.severity || 'low'}">${alert.severity || 'low'}</span>
            </div>
        `).join('');
    }

    async loadThreatLogs() {
        try {
            const severityFilter = document.getElementById('logSeverityFilter').value;
            const url = severityFilter ? `/api/threats?severity=${severityFilter}&limit=${this.maxLogs}` : `/api/threats?limit=${this.maxLogs}`;
            const response = await this.apiCall(url);
            this.displayThreatLogs(response.threats || []);
        } catch (error) {
            this.showToast('Failed to load threat logs', 'error');
            console.error('Threat logs load error:', error);
        }
    }

    displayThreatLogs(threats) {
        const threatsList = document.getElementById('threatsList');
        if (threats.length === 0) {
            threatsList.innerHTML = `
                <div class="threat-item low">
                    <div class="threat-header">
                        <span class="threat-type">No Threats Logged</span>
                        <span class="threat-severity low">Safe</span>
                    </div>
                    <div class="threat-description">
                        No threats have been detected and logged.
                    </div>
                </div>
            `;
            return;
        }
        threatsList.innerHTML = threats.map(threat => {
            let customClass = '';
            let extraInfo = '';
            if (threat.type === 'ml_detected_threat') {
                customClass = 'ml_detected_threat';
                extraInfo = '<div class="threat-extra">Detected by <b>ML Model</b> 🤖</div>';
            } else if (threat.type === 'anomaly_detected') {
                customClass = 'anomaly_detected';
                extraInfo = '<div class="threat-extra">Anomaly: <b>High request rate</b> ⚠️</div>';
            }
            return `
            <div class="threat-item ${threat.severity} ${customClass}" data-threat-id="${threat.id}">
                <div class="threat-header">
                    <span class="threat-type ${customClass}">${threat.type}</span>
                    <div class="threat-actions">
                        <span class="threat-severity ${threat.severity}">${threat.severity}</span>
                    </div>
                </div>
                <div class="threat-description">${threat.description}${extraInfo}</div>
                <div class="threat-meta">
                    <span>Confidence: ${Math.round(threat.confidence * 100)}%</span>
                    <span>Method: ${threat.detection_method}</span>
                    <span>Source: ${threat.source_ip || 'Unknown'}</span>
                    <span>Time: ${this.formatTime(threat.timestamp)}</span>
                </div>
            </div>
            `;
        }).join('');
    }

    async deleteThreat(threatId) {
        try {
            console.log('Attempting to delete threat:', threatId);
            this.showLoading();
            
            const response = await this.apiCall(`/api/threats/${threatId}`, {
                method: 'DELETE'
            });
            
            console.log('Delete response:', response);
            this.hideLoading();
            
            if (response.message) {
                this.showToast('Threat deleted successfully', 'success');
                
                // Reload threat logs to reflect the deletion
                await this.loadThreatLogs();
                
                // Reload dashboard to update counts
                await this.loadDashboard();
                
                // Reload analytics to update charts
                await this.loadAnalytics();
            }
        } catch (error) {
            console.error('Delete threat error details:', error);
            this.hideLoading();
            this.showToast('Failed to delete threat', 'error');
            console.error('Delete threat error:', error);
        }
    }

    filterThreatLogs(searchTerm) {
        const threatItems = document.querySelectorAll('.threats-list .threat-item');
        
        threatItems.forEach(item => {
            const text = item.textContent.toLowerCase();
            const matches = text.includes(searchTerm.toLowerCase());
            item.style.display = matches ? 'block' : 'none';
        });
    }

    initializeCharts() {
        // Initialize empty charts
        const threatCtx = document.getElementById('threatChart').getContext('2d');
        this.charts.threatChart = new Chart(threatCtx, {
            type: 'doughnut',
            data: {
                labels: ['No Data'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['#e5e7eb']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });

        const severityCtx = document.getElementById('severityChart').getContext('2d');
        this.charts.severityChart = new Chart(severityCtx, {
            type: 'bar',
            data: {
                labels: ['No Data'],
                datasets: [{
                    label: 'Threats by Severity',
                    data: [0],
                    backgroundColor: ['#e5e7eb']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    startAutoRefresh() {
        if (this.autoRefresh) {
            this.refreshTimer = setInterval(() => {
                this.loadDashboard();
            }, this.refreshInterval);
        }
    }

    stopAutoRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
    }

    async apiCall(endpoint, options = {}) {
        const url = `${this.apiUrl}${endpoint}`;
        const config = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            ...options
        };

        const response = await fetch(url, config);
        
        if (!response.ok) {
            throw new Error(`API call failed: ${response.status} ${response.statusText}`);
        }

        return await response.json();
    }

    showLoading() {
        document.getElementById('loadingOverlay').style.display = 'flex';
    }

    hideLoading() {
        document.getElementById('loadingOverlay').style.display = 'none';
    }

    showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle'
        }[type];

        toast.innerHTML = `
            <i class="${icon}"></i>
            <span>${message}</span>
        `;

        toastContainer.appendChild(toast);

        // Auto remove after 5 seconds
        setTimeout(() => {
            toast.remove();
        }, 5000);
    }

    formatTime(timestamp) {
        if (!timestamp) return 'Unknown';
        
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
        if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
        return date.toLocaleDateString();
    }

    loadSampleData() {
        const samples = [
            {
                name: 'SQL Injection',
                data: {
                    source_ip: '192.168.1.100',
                    user_agent: 'sqlmap/1.0',
                    url: 'http://example.com/admin?id=1\' OR \'1\'=\'1',
                    port: 80
                }
            },
            {
                name: 'XSS Attack',
                data: {
                    source_ip: '192.168.1.101',
                    user_agent: 'Mozilla/5.0',
                    url: 'http://example.com/search?q=<script>alert("xss")</script>',
                    port: 80
                }
            },
            {
                name: 'Suspicious Port',
                data: {
                    source_ip: '192.168.1.102',
                    port: 22,
                    protocol: 'ssh'
                }
            }
        ];

        const randomSample = samples[Math.floor(Math.random() * samples.length)];
        
        Object.entries(randomSample.data).forEach(([key, value]) => {
            const element = document.getElementById(key.replace('_', ''));
            if (element) {
                element.value = value;
            }
        });

        this.showToast(`Loaded sample: ${randomSample.name}`, 'info');
    }

    clearForm() {
        document.getElementById('threatDetectionForm').reset();
        document.getElementById('resultsCard').style.display = 'none';
    }

    refreshThreatFeed() {
        this.loadDashboard();
        this.showToast('Threat feed refreshed', 'info');
    }

    refreshAlerts() {
        this.loadAlerts();
        this.showToast('Alerts refreshed', 'info');
    }

    refreshLogs() {
        this.loadThreatLogs();
        this.showToast('Threat logs refreshed', 'info');
    }

    resetSettings() {
        this.apiUrl = 'http://localhost:5000';
        this.refreshInterval = 30000;
        this.autoRefresh = true;
        this.maxLogs = 100;
        
        // Update form fields
        document.getElementById('apiUrl').value = this.apiUrl;
        document.getElementById('refreshInterval').value = this.refreshInterval;
        document.getElementById('autoRefresh').value = this.autoRefresh;
        document.getElementById('maxLogs').value = this.maxLogs;
        
        this.saveSettings();
        this.showToast('Settings reset to defaults', 'info');
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.threatDetectionUI = new ThreatDetectionUI();
});

// Utility functions for global access
window.loadSampleData = () => window.threatDetectionUI.loadSampleData();
window.clearForm = () => window.threatDetectionUI.clearForm();
window.refreshThreatFeed = () => window.threatDetectionUI.refreshThreatFeed();
window.refreshAlerts = () => window.threatDetectionUI.refreshAlerts();
window.refreshLogs = () => window.threatDetectionUI.refreshLogs();
window.resetSettings = () => window.threatDetectionUI.resetSettings(); 