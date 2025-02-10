// JavaScript for handling IP analysis functionality

document.getElementById('analyze_button').addEventListener('click', function() {
    const ipAddress = document.getElementById('ip_address').value;
    // Show loading state
    document.getElementById('loading_indicator').style.display = 'block';
    
    // Call the backend API to analyze the IP address
    fetch(`/threat/ip-analysis/analyze/${ipAddress}/`)
        .then(response => response.json())
        .then(data => {
            // Hide loading state
            document.getElementById('loading_indicator').style.display = 'none';
            
            // Update the UI with the results from summary
            document.getElementById('threat_score').innerText = data.summary.threat_score || 'N/A';
            document.getElementById('confidence_score').innerText = data.summary.confidence || 'N/A';
            document.getElementById('risk_level').innerText = data.summary.risk_level || 'Unknown';
            
            // Update WHOIS info if available
            const whoisInfo = data.platform_data.ipinfo || {};
            document.getElementById('whois_info').innerHTML = '';
            const whoisTable = document.createElement('table');
            whoisTable.className = 'whois-info-table';
            whoisTable.innerHTML = `<thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>`;
            
            // Map of user-friendly names for WHOIS fields
            const fieldNames = {
                'ip': 'IP Address',
                'hostname': 'Hostname',
                'city': 'City',
                'region': 'Region',
                'country': 'Country',
                'org': 'Organization',
                'asn': 'ASN',
                'timezone': 'Timezone'
            };
            
            Object.entries(whoisInfo).forEach(([key, value]) => {
                if (fieldNames[key] && value) {
                    whoisTable.innerHTML += `<tr><td>${fieldNames[key]}</td><td>${value}</td></tr>`;
                }
            });
            
            whoisTable.innerHTML += `</tbody>`;
            document.getElementById('whois_info').appendChild(whoisTable);
            
            // Update platform scores
            updatePlatformScores(data.platform_data);
            
            // Update threat score gauge
            updateThreatGauge(data.summary.threat_score);
            
            // Update risk level badge
            updateRiskBadge(data.summary.risk_level);
            
            // Initialize map if coordinates are available from IPInfo
            const ipinfoData = data.platform_data.ipinfo || {};
            if (ipinfoData.latitude && ipinfoData.longitude) {
                initMap(ipinfoData.latitude, ipinfoData.longitude);
            }
            
            // Initialize platform score charts
            initPlatformCharts(data.summary.platform_scores);
            
            // Initialize all charts
            initializeCharts(data);
            
            // Show any errors
            const errorsDiv = document.getElementById('scan_errors');
            if (data.summary.errors && Object.keys(data.summary.errors).length > 0) {
                errorsDiv.innerHTML = '<h4>Scan Errors:</h4>';
                Object.entries(data.summary.errors).forEach(([platform, error]) => {
                    errorsDiv.innerHTML += `<p><strong>${platform}:</strong> ${error}</p>`;
                });
                errorsDiv.style.display = 'block';
            } else {
                errorsDiv.style.display = 'none';
            }
        })
        .catch(error => {
            // Hide loading state and show error
            document.getElementById('loading_indicator').style.display = 'none';
            document.getElementById('scan_errors').innerHTML = `<p>Error analyzing IP: ${error.message}</p>`;
            document.getElementById('scan_errors').style.display = 'block';
        });
});

function updatePlatformScores(platformData) {
    const platformScoresDiv = document.getElementById('platform_scores');
    platformScoresDiv.innerHTML = '';
    
    Object.entries(platformData).forEach(([platform, data]) => {
        if (data && typeof data === 'object' && !data.error) {
            const scoreDiv = document.createElement('div');
            scoreDiv.className = 'platform-score-container';
            
            // Create header with platform name
            const header = document.createElement('h4');
            header.innerText = platform.charAt(0).toUpperCase() + platform.slice(1);
            scoreDiv.appendChild(header);
            
            // Create table for platform data
            const table = document.createElement('table');
            table.className = 'table table-striped table-responsive';
            table.innerHTML = `<thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>`;
            
            // Add relevant fields based on platform
            Object.entries(data).forEach(([key, value]) => {
                // Skip null/undefined values and complex objects
                if (value != null && typeof value !== 'object') {
                    table.innerHTML += `<tr><td>${key}</td><td>${value}</td></tr>`;
                }
            });
            
            table.innerHTML += `</tbody>`;
            scoreDiv.appendChild(table);
            platformScoresDiv.appendChild(scoreDiv);
        }
    });
}

// IP Analysis JavaScript

// Initialize data tables
$(document).ready(function() {
    $('.datatable').DataTable({
        pageLength: 10,
        order: [[2, 'desc']],  // Sort by confidence by default
        responsive: true
    });
});

// Platform score chart colors
const platformColors = {
    'virustotal': '#4CAF50',
    'abuseipdb': '#2196F3',
    'greynoise': '#9C27B0',
    'crowdsec': '#FF5722',
    'securitytrails': '#795548',
    'ipinfo': '#607D8B',
    'metadefender': '#F44336',
    'pulsedive': '#FFC107',
    'alienvault': '#00BCD4'
};

// Initialize platform score charts
function initPlatformCharts(platformScores) {
    Object.entries(platformScores).forEach(([platform, data]) => {
        const chartId = `${platform}Chart`;
        const ctx = document.getElementById(chartId);
        if (ctx) {
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Score'],
                    datasets: [{
                        data: [data.score],
                        backgroundColor: platformColors[platform] || '#999',
                        borderWidth: 0
                    }]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
        }
    });
}

// Update threat score gauge
function updateThreatGauge(score) {
    const gauge = document.getElementById('threatScoreGauge');
    if (gauge) {
        const ctx = gauge.getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [
                        getScoreColor(score),
                        '#eee'
                    ]
                }]
            },
            options: {
                cutoutPercentage: 70,
                rotation: Math.PI,
                circumference: Math.PI,
                tooltips: {
                    enabled: false
                }
            }
        });
    }
}

// Get color based on score
function getScoreColor(score) {
    if (score >= 80) return '#dc3545';  // Critical - Red
    if (score >= 60) return '#fd7e14';  // High - Orange
    if (score >= 40) return '#ffc107';  // Medium - Yellow
    if (score >= 20) return '#28a745';  // Low - Green
    return '#17a2b8';                   // Safe - Blue
}

// Get risk level based on score
function getRiskLevel(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 40) return 'Medium';
    if (score >= 20) return 'Low';
    return 'Safe';
}

// Update risk level badge
function updateRiskBadge(level) {
    const badge = document.getElementById('riskLevelBadge');
    if (badge) {
        badge.className = 'badge badge-' + getRiskLevelClass(level);
        badge.textContent = level;
    }
}

// Get badge class based on risk level
function getRiskLevelClass(level) {
    const map = {
        'Critical': 'danger',
        'High': 'warning',
        'Medium': 'info',
        'Low': 'success',
        'Safe': 'primary'
    };
    return map[level] || 'secondary';
}

// Initialize map if coordinates are available
function initMap(lat, lon) {
    if (lat && lon && typeof L !== 'undefined') {
        const map = L.map('locationMap').setView([lat, lon], 13);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: ' OpenStreetMap contributors'
        }).addTo(map);
        L.marker([lat, lon]).addTo(map);
    }
}

// Export data as JSON
function exportData() {
    const data = {
        ip_address: document.getElementById('ipAddress').textContent,
        threat_score: parseFloat(document.getElementById('threatScore').textContent),
        risk_level: document.getElementById('riskLevel').textContent,
        platform_scores: window.platformScores,
        threats: window.threats,
        activities: window.activities,
        malware: window.malware
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ip_analysis_${data.ip_address}_${new Date().toISOString()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Initialize all charts when data is loaded
function initializeCharts(data) {
    initPlatformCharts(data.summary.platform_scores);
    initNetworkInfraChart(data.enhanced_analysis.infrastructure);
    initDNSHistoryChart(data.enhanced_analysis.dns_history);
    initMitreHeatmap(data.enhanced_analysis.mitre_mapping);
    initReputationTimeline(data.enhanced_analysis.historical_reputation);
}

// Network Infrastructure Chart
function initNetworkInfraChart(data) {
    const ctx = document.getElementById('networkInfraChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: Object.keys(data),
            datasets: [{
                data: Object.values(data),
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 2
            }]
        },
        options: {
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
}

// DNS History Chart
function initDNSHistoryChart(data) {
    const ctx = document.getElementById('dnsHistoryChart');
    if (!ctx) return;

    const dates = data.map(record => record.date);
    const records = data.map(record => record.count);

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [{
                label: 'DNS Records',
                data: records,
                borderColor: 'rgba(54, 162, 235, 1)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// MITRE ATT&CK Heatmap
function initMitreHeatmap(data) {
    const ctx = document.getElementById('mitreHeatmap');
    if (!ctx) return;

    const tactics = [...new Set(data.map(t => t.tactic))];
    const techniques = data.map(t => ({
        x: tactics.indexOf(t.tactic),
        y: parseInt(t.id.replace('T', '')),
        v: t.confidence
    }));

    new Chart(ctx, {
        type: 'matrix',
        data: {
            datasets: [{
                data: techniques,
                backgroundColor(context) {
                    const value = context.dataset.data[context.dataIndex].v;
                    const alpha = value / 100;
                    return `rgba(255, 99, 132, ${alpha})`;
                }
            }]
        },
        options: {
            scales: {
                x: {
                    type: 'category',
                    labels: tactics
                },
                y: {
                    type: 'category',
                    labels: data.map(t => t.id)
                }
            }
        }
    });
}

// Historical Reputation Timeline
function initReputationTimeline(data) {
    const ctx = document.getElementById('reputationTimeline');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(point => point.date),
            datasets: [{
                label: 'Reputation Score',
                data: data.map(point => point.score),
                borderColor: 'rgba(153, 102, 255, 1)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
}

// Update active services display
function updateActiveServices(services) {
    const container = document.getElementById('activeServices');
    if (!container) return;

    container.innerHTML = '';
    services.forEach(service => {
        const serviceEl = document.createElement('div');
        serviceEl.className = 'border p-4 rounded-lg';
        serviceEl.innerHTML = `
            <div class="flex items-center justify-between mb-2">
                <span class="font-semibold">${service.port}/${service.protocol}</span>
                <span class="badge ${getRiskBadgeClass(service.risk_level)}">${service.risk_level}</span>
            </div>
            <div class="text-sm text-white-dark">
                <div>Service: ${service.name}</div>
                <div>Version: ${service.version}</div>
                <div>Status: ${service.status}</div>
            </div>
        `;
        container.appendChild(serviceEl);
    });
}

// Get risk badge class
function getRiskBadgeClass(level) {
    const classes = {
        high: 'badge-danger',
        medium: 'badge-warning',
        low: 'badge-success'
    };
    return classes[level] || 'badge-secondary';
}

// Export enhanced analysis data
function exportEnhancedData() {
    const data = {
        ip_address: document.getElementById('ipAddress').textContent,
        analysis_date: new Date().toISOString(),
        threat_summary: {
            threat_score: parseFloat(document.getElementById('threatScore').textContent),
            risk_level: document.getElementById('riskLevel').textContent,
            platform_scores: window.platformScores
        },
        enhanced_analysis: {
            network_info: window.networkInfo,
            ssl_certificates: window.sslCertificates,
            dns_history: window.dnsHistory,
            infrastructure: window.infrastructure,
            active_services: window.activeServices,
            mitre_mapping: window.mitreMapping,
            related_iocs: window.relatedIocs,
            historical_reputation: window.historicalReputation
        }
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `enhanced_ip_analysis_${data.ip_address}_${new Date().toISOString()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Update all visualizations when new data is received
document.addEventListener('alpine:init', () => {
    Alpine.data('ipAnalysis', () => ({
        // ...existing Alpine.js data...
        
        async analyzeIP() {
            if (!this.ipAddress) {
                this.error = 'Please enter an IP address';
                return;
            }
            
            this.isLoading = true;
            this.error = null;
            
            try {
                const response = await fetch(`/threat/ip-analysis/analyze/${this.ipAddress}/`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`Failed to analyze IP: ${response.status} ${response.statusText}`);
                }
                
                this.results = await response.json();
                
                // Store data in window for export functionality
                window.networkInfo = this.results.enhanced_analysis.network_info;
                window.sslCertificates = this.results.enhanced_analysis.ssl_certificates;
                window.dnsHistory = this.results.enhanced_analysis.dns_history;
                window.infrastructure = this.results.enhanced_analysis.infrastructure;
                window.activeServices = this.results.enhanced_analysis.active_services;
                window.mitreMapping = this.results.enhanced_analysis.mitre_mapping;
                window.relatedIocs = this.results.enhanced_analysis.related_iocs;
                window.historicalReputation = this.results.enhanced_analysis.historical_reputation;
                
                // Initialize all charts and visualizations
                initializeCharts(this.results);
                
                // Update other UI components
                updateActiveServices(this.results.enhanced_analysis.active_services);
                this.activeTab = 'overview';
                
            } catch (err) {
                console.error('Error analyzing IP:', err);
                this.error = err.message;
            } finally {
                this.isLoading = false;
            }
        }
    }));
});
