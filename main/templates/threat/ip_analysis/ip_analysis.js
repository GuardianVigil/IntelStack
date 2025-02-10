// JavaScript for handling IP analysis functionality
document.getElementById('analyze_button').addEventListener('click', function() {
    const ipAddress = document.getElementById('ip_address').value;
    document.getElementById('loading_indicator').style.display = 'block';
    
    fetch(`/threat/ip-analysis/analyze/${ipAddress}/`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('loading_indicator').style.display = 'none';
            
            // Update summary information
            updateSummaryInfo(data.summary);
            
            // Update WHOIS information
            updateWhoisInfo(data.platform_data.ipinfo);
            
            // Update platform results
            updatePlatformResults(data.platform_data);
            
            // Initialize map if coordinates are available
            const ipinfo = data.platform_data.ipinfo || {};
            if (ipinfo.latitude && ipinfo.longitude) {
                initMap(ipinfo.latitude, ipinfo.longitude);
            }
            
            // Show any errors
            updateErrorDisplay(data.summary.errors);
        })
        .catch(error => {
            handleError(error);
        });
});

function updateSummaryInfo(summary) {
    document.getElementById('threat_score').innerText = summary.threat_score || 'N/A';
    document.getElementById('confidence_score').innerText = summary.confidence || 'N/A';
    document.getElementById('risk_level').innerText = summary.risk_level || 'Unknown';
    updateRiskBadge(summary.risk_level);
    updateThreatGauge(summary.threat_score);
}

function updateWhoisInfo(whoisData) {
    if (!whoisData) return;
    
    const whoisContainer = document.getElementById('whois_info');
    whoisContainer.innerHTML = '';
    
    const table = document.createElement('table');
    table.className = 'whois-info-table';
    table.innerHTML = '<thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>';
    
    const fields = {
        'ip': 'IP Address',
        'hostname': 'Hostname',
        'city': 'City',
        'region': 'Region',
        'country': 'Country',
        'organization': 'Organization',
        'asn': 'ASN',
        'timezone': 'Timezone',
        'postal': 'Postal Code'
    };
    
    for (const [key, label] of Object.entries(fields)) {
        if (whoisData[key]) {
            table.innerHTML += `
                <tr>
                    <td>${label}</td>
                    <td>${whoisData[key]}</td>
                </tr>
            `;
        }
    }
    
    table.innerHTML += '</tbody>';
    whoisContainer.appendChild(table);
}

function updatePlatformResults(platformData) {
    const platformContainer = document.getElementById('platform_scores');
    platformContainer.innerHTML = '';
    
    Object.entries(platformData).forEach(([platform, data]) => {
        // Skip if no data or error
        if (!data || data.error) return;
        
        const platformDiv = document.createElement('div');
        platformDiv.className = 'platform-section mb-4';
        
        // Platform header
        platformDiv.innerHTML = `<h3 class="platform-title">${platform.toUpperCase()}</h3>`;
        
        // Handle both array and object formats
        if (Array.isArray(data)) {
            // Handle array of sections
            data.forEach(section => {
                platformDiv.appendChild(createSectionElement(section));
            });
        } else if (typeof data === 'object') {
            // Handle single object format (like IPInfo)
            const table = document.createElement('table');
            table.className = 'table table-striped';
            table.innerHTML = '<tbody>';
            
            Object.entries(data).forEach(([key, value]) => {
                if (value && typeof value !== 'object') {
                    table.innerHTML += `
                        <tr>
                            <td>${key.replace('_', ' ').toUpperCase()}</td>
                            <td>${value}</td>
                        </tr>
                    `;
                }
            });
            
            table.innerHTML += '</tbody>';
            platformDiv.appendChild(table);
        }
        
        platformContainer.appendChild(platformDiv);
    });
}

function createSectionElement(section) {
    const sectionDiv = document.createElement('div');
    sectionDiv.className = 'mb-3';
    
    // Add section name if available
    if (section.name) {
        sectionDiv.innerHTML = `<h4 class="section-title">${section.name}</h4>`;
    }
    
    // Handle different section types
    if (section.type === 'table') {
        sectionDiv.appendChild(createTableElement(section));
    } else if (section.type === 'datatable') {
        sectionDiv.appendChild(createDataTableElement(section));
    } else if (section.type === 'single') {
        sectionDiv.innerHTML += `<p>${section.value}</p>`;
    }
    
    return sectionDiv;
}

function createTableElement(section) {
    const table = document.createElement('table');
    table.className = 'table table-striped';
    
    let tableHTML = '<thead><tr>';
    section.headers.forEach(header => {
        tableHTML += `<th>${header}</th>`;
    });
    tableHTML += '</tr></thead><tbody>';
    
    section.rows.forEach(row => {
        tableHTML += '<tr>';
        row.forEach(cell => {
            tableHTML += `<td>${cell}</td>`;
        });
        tableHTML += '</tr>';
    });
    
    tableHTML += '</tbody>';
    table.innerHTML = tableHTML;
    return table;
}

function createDataTableElement(section) {
    const table = document.createElement('table');
    table.className = 'table table-striped datatable';
    
    let tableHTML = '<thead><tr>';
    section.headers.forEach(header => {
        tableHTML += `<th>${header}</th>`;
    });
    tableHTML += '</tr></thead><tbody>';
    
    section.rows.forEach(row => {
        tableHTML += '<tr>';
        row.forEach(cell => {
            tableHTML += `<td>${cell}</td>`;
        });
        tableHTML += '</tr>';
    });
    
    tableHTML += '</tbody>';
    table.innerHTML = tableHTML;
    
    // Initialize as DataTable
    $(table).DataTable({
        pageLength: 10,
        responsive: true
    });
    
    return table;
}

function updateErrorDisplay(errors) {
    const errorsDiv = document.getElementById('scan_errors');
    if (errors && Object.keys(errors).length > 0) {
        errorsDiv.innerHTML = '<h4>Scan Errors:</h4>';
        Object.entries(errors).forEach(([platform, error]) => {
            errorsDiv.innerHTML += `<p><strong>${platform}:</strong> ${error}</p>`;
        });
        errorsDiv.style.display = 'block';
    } else {
        errorsDiv.style.display = 'none';
    }
}

function handleError(error) {
    document.getElementById('loading_indicator').style.display = 'none';
    document.getElementById('scan_errors').innerHTML = `<p>Error analyzing IP: ${error.message}</p>`;
    document.getElementById('scan_errors').style.display = 'block';
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
        ipAddress: '',
        results: null,
        loading: false,
        error: null,

        initTable(table) {
            if (!table.pageSize) {
                table.pageSize = 10;
                table.currentPage = 1;
                table.searchTerm = '';
                table.sortBy = null;
                table.sortDesc = false;

                Object.defineProperty(table, 'filteredRows', {
                    get() {
                        let filtered = [...this.rows];
                        
                        // Apply search
                        if (this.searchTerm) {
                            const searchLower = this.searchTerm.toLowerCase();
                            filtered = filtered.filter(row => 
                                row.some(cell => 
                                    String(cell).toLowerCase().includes(searchLower)
                                )
                            );
                        }
                        
                        // Apply sort
                        if (this.sortBy !== null) {
                            filtered.sort((a, b) => {
                                const aVal = String(a[this.sortBy]).toLowerCase();
                                const bVal = String(b[this.sortBy]).toLowerCase();
                                return this.sortDesc 
                                    ? bVal.localeCompare(aVal)
                                    : aVal.localeCompare(bVal);
                            });
                        }
                        
                        return filtered;
                    }
                });

                Object.defineProperty(table, 'paginatedRows', {
                    get() {
                        const start = (this.currentPage - 1) * this.pageSize;
                        return this.filteredRows.slice(start, start + this.pageSize);
                    }
                });
            }
            return table;
        },

        async analyzeIP() {
            if (!this.ipAddress) return;
            
            this.loading = true;
            this.error = null;
            
            try {
                const response = await fetch(`/threat/ip-analysis/analyze/${this.ipAddress}/`);
                if (!response.ok) {
                    throw new Error('Failed to analyze IP');
                }
                
                const data = await response.json();
                this.results = data;
                
                // Initialize datatables for any table with type 'datatable'
                if (this.results && this.results.platform_data) {
                    Object.values(this.results.platform_data).forEach(platform => {
                        if (Array.isArray(platform)) {
                            platform.forEach(table => {
                                if (table.type === 'datatable') {
                                    this.initTable(table);
                                }
                            });
                        }
                    });
                }
                
            } catch (err) {
                this.error = err.message;
                console.error('Error analyzing IP:', err);
            } finally {
                this.loading = false;
            }
        }
    }));
});
