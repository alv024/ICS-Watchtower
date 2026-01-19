// Dashboard JavaScript for ICS Vulnerability Watchtower

// Chart instances
let severityChart = null;
let timelineChart = null;
let vendorChart = null;
let kevStatusChart = null;

// Auto-refresh interval (5 minutes)
const REFRESH_INTERVAL = 5 * 60 * 1000;
let refreshTimer = null;

// Current days parameter
let currentDays = 30; // Default, will be set from page

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', function() {
    // Get initial days value from input
    const daysInput = document.getElementById('days-input');
    if (daysInput) {
        currentDays = parseInt(daysInput.value) || 30;
    }
    
    // Setup days selector
    const updateBtn = document.getElementById('update-days-btn');
    if (updateBtn) {
        updateBtn.addEventListener('click', updateDays);
    }
    
    // Setup diagnostics button
    const diagnosticsBtn = document.getElementById('diagnostics-btn');
    if (diagnosticsBtn) {
        diagnosticsBtn.addEventListener('click', runDiagnostics);
    }
    
    // Allow Enter key to trigger update
    if (daysInput) {
        daysInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                updateDays();
            }
        });
    }
    
    loadData();
    startAutoRefresh();
});

/**
 * Update days parameter and reload data
 */
function updateDays() {
    const daysInput = document.getElementById('days-input');
    if (daysInput) {
        const newDays = parseInt(daysInput.value);
        if (newDays >= 1 && newDays <= 365) {
            currentDays = newDays;
            loadData();
        } else {
            alert('Days must be between 1 and 365');
            daysInput.value = currentDays;
        }
    }
}

/**
 * Load data from API endpoints and update dashboard
 */
async function loadData() {
    try {
        // Load statistics and data in parallel with days parameter
        const daysParam = `?days=${currentDays}`;
        const [statsResponse, dataResponse] = await Promise.all([
            fetch(`/api/stats${daysParam}`),
            fetch(`/api/data${daysParam}`)
        ]);

        if (!statsResponse.ok || !dataResponse.ok) {
            throw new Error('Failed to fetch data');
        }

        const statsData = await statsResponse.json();
        const dataData = await dataResponse.json();

        if (statsData.success && dataData.success) {
            updateStatistics(statsData.stats);
            updateCharts(statsData.stats);
            updateVulnerabilities(dataData.data);
            updateLastUpdated(dataData.last_updated);
        }
    } catch (error) {
        console.error('Error loading data:', error);
        document.getElementById('last-updated').textContent = 'Error loading data';
    }
}

/**
 * Update statistics cards
 */
function updateStatistics(stats) {
    document.getElementById('stat-total').textContent = stats.total_ics || 0;
    document.getElementById('stat-critical').textContent = stats.critical_count || 0;
    document.getElementById('stat-kev').textContent = stats.cisa_kev_count || 0;
    document.getElementById('stat-nvd').textContent = stats.total_nvd || 0;
    
    // Update days display
    const days = stats.days || currentDays;
    const daysLabel = days === 1 ? '1 day' : `${days} days`;
    document.getElementById('stat-days').textContent = `Last ${daysLabel}`;
}

/**
 * Update all charts
 */
function updateCharts(stats) {
    updateSeverityChart(stats.severity_distribution);
    updateTimelineChart(stats.timeline_dates, stats.timeline_counts);
    updateVendorChart(stats.vendor_labels, stats.vendor_counts);
    updateKEVStatusChart(stats.cisa_kev_count, stats.nvd_only_count);
}

/**
 * Update severity distribution chart
 */
function updateSeverityChart(severityData) {
    const ctx = document.getElementById('severity-chart').getContext('2d');
    
    // Define colors for each severity
    const colors = {
        'CRITICAL': '#ff6b6b',
        'HIGH': '#ffa726',
        'MEDIUM': '#ffeb3b',
        'LOW': '#66bb6a',
        'Unknown': '#bdbdbd'
    };

    const labels = Object.keys(severityData);
    const data = Object.values(severityData);
    const backgroundColors = labels.map(label => colors[label] || colors['Unknown']);

    if (severityChart) {
        severityChart.destroy();
    }

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColors,
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

/**
 * Update timeline chart
 */
function updateTimelineChart(dates, counts) {
    const ctx = document.getElementById('timeline-chart').getContext('2d');
    
    if (timelineChart) {
        timelineChart.destroy();
    }

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates || [],
            datasets: [{
                label: 'Vulnerabilities',
                data: counts || [],
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
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

/**
 * Update vendor/product chart
 */
function updateVendorChart(labels, counts) {
    const ctx = document.getElementById('vendor-chart').getContext('2d');
    
    if (vendorChart) {
        vendorChart.destroy();
    }

    vendorChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels || [],
            datasets: [{
                label: 'Vulnerabilities',
                data: counts || [],
                backgroundColor: '#667eea',
                borderColor: '#5568d3',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'y',
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
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

/**
 * Update CISA KEV status chart
 */
function updateKEVStatusChart(kevCount, nvdOnlyCount) {
    const ctx = document.getElementById('kev-status-chart').getContext('2d');
    
    if (kevStatusChart) {
        kevStatusChart.destroy();
    }

    kevStatusChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['CISA KEV', 'NVD Only'],
            datasets: [{
                data: [kevCount || 0, nvdOnlyCount || 0],
                backgroundColor: ['#ff6b6b', '#667eea'],
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

/**
 * Update vulnerabilities list
 */
function updateVulnerabilities(vulnerabilities) {
    const container = document.getElementById('vulnerabilities-container');
    
    if (!vulnerabilities || vulnerabilities.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <h3>✅ Good News!</h3>
                <p>No new ICS-related vulnerabilities found in the last 7 days.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = vulnerabilities.map(vuln => {
        const severityClass = vuln.severity_rating ? vuln.severity_rating.toLowerCase() : 'unknown';
        const cardClass = vuln.severity_rating ? vuln.severity_rating.toLowerCase() : 'unknown';
        const cveIdClass = vuln.is_cisa_kev ? 'cisa-kev' : '';
        
        let detailsHtml = '';
        if (vuln.is_cisa_kev && vuln.vendor_project) {
            detailsHtml = `
                <div class="vuln-details">
                    <strong>Vendor:</strong> ${vuln.vendor_project || 'N/A'}
                    ${vuln.product ? ` | <strong>Product:</strong> ${vuln.product}` : ''}
                    ${vuln.due_date ? ` | <strong>Due Date:</strong> ${vuln.due_date}` : ''}
                    ${vuln.known_ransomware_use && vuln.known_ransomware_use !== 'Unknown' 
                        ? ` | <strong>Ransomware:</strong> ${vuln.known_ransomware_use}` : ''}
                </div>
            `;
        }

        return `
            <div class="vuln-card ${cardClass}">
                <div class="vuln-header">
                    <div>
                        <div class="vuln-id ${cveIdClass}">${vuln.cve_id}</div>
                        <div class="vuln-meta">
                            <span><strong>Published:</strong> ${vuln.published_date}</span>
                            ${vuln.severity_score ? `<span><strong>CVSS:</strong> ${vuln.severity_score.toFixed(1)}</span>` : ''}
                            <span><strong>Source:</strong> ${vuln.source}</span>
                        </div>
                    </div>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        ${vuln.severity_rating ? `<span class="severity-badge ${severityClass}">${vuln.severity_rating}</span>` : ''}
                        ${vuln.is_cisa_kev ? '<span class="kev-badge">⚠️ CISA KEV</span>' : ''}
                    </div>
                </div>
                <div class="vuln-description">
                    ${vuln.description || 'No description available'}
                </div>
                ${detailsHtml}
            </div>
        `;
    }).join('');
}

/**
 * Update last updated timestamp
 */
function updateLastUpdated(timestamp) {
    const date = new Date(timestamp);
    const formatted = date.toLocaleString();
    document.getElementById('last-updated').textContent = `Last updated: ${formatted}`;
}

/**
 * Start auto-refresh timer
 */
function startAutoRefresh() {
    refreshTimer = setInterval(() => {
        loadData();
    }, REFRESH_INTERVAL);
}

/**
 * Stop auto-refresh timer
 */
function stopAutoRefresh() {
    if (refreshTimer) {
        clearInterval(refreshTimer);
        refreshTimer = null;
    }
}

/**
 * Run diagnostics to check CISA KEV and NVD overlap
 */
async function runDiagnostics() {
    const diagnosticsBtn = document.getElementById('diagnostics-btn');
    const originalText = diagnosticsBtn.textContent;
    diagnosticsBtn.disabled = true;
    diagnosticsBtn.textContent = 'Running...';
    
    try {
        const response = await fetch('/api/diagnostics');
        if (!response.ok) {
            throw new Error('Failed to fetch diagnostics');
        }
        
        const data = await response.json();
        if (data.success) {
            displayDiagnostics(data.diagnostics);
        }
    } catch (error) {
        console.error('Error running diagnostics:', error);
        alert('Error running diagnostics: ' + error.message);
    } finally {
        diagnosticsBtn.disabled = false;
        diagnosticsBtn.textContent = originalText;
    }
}

/**
 * Display diagnostics results
 */
function displayDiagnostics(diag) {
    const explanation = diag.explanation;
    const details = diag.overlap_details || [];
    
    let message = `\n=== CISA KEV vs NVD Overlap Analysis ===\n\n`;
    message += `CISA KEV (last 30 days): ${diag.cisa_kev_recent_count} entries\n`;
    message += `CISA KEV (total catalog): ${diag.cisa_kev_total_count} entries\n`;
    message += `NVD (last 30 days): ${diag.nvd_recent_count} CVEs\n\n`;
    message += `Overlap (recent): ${diag.overlap_recent_count} CVEs\n`;
    message += `Overlap (all CISA vs recent NVD): ${diag.overlap_all_count} CVEs\n`;
    message += `CISA KEV CVEs NOT in recent NVD: ${diag.cisa_not_in_nvd_recent}\n\n`;
    message += `\n📋 Explanation:\n${explanation.issue}\n\n`;
    message += `✅ Result: ${explanation.result}\n`;
    message += `ℹ️  Note: ${explanation.note}\n\n`;
    
    if (details.length > 0) {
        message += `\n📊 Overlapping CVEs (${details.length}):\n`;
        details.forEach(item => {
            message += `\n  ${item.cve_id}:\n`;
            message += `    CISA dateAdded: ${item.cisa_date_added}\n`;
            message += `    NVD published: ${item.nvd_published}\n`;
            message += `    CVSS: ${item.nvd_cvss || 'N/A'} (${item.severity})\n`;
        });
    }
    
    if (diag.cisa_not_in_nvd_list && diag.cisa_not_in_nvd_list.length > 0) {
        message += `\n\n⚠️  Sample CISA KEV CVEs NOT in recent NVD (first 10):\n`;
        diag.cisa_not_in_nvd_list.slice(0, 10).forEach(cve_id => {
            message += `  - ${cve_id}\n`;
        });
        if (diag.cisa_not_in_nvd_list.length > 10) {
            message += `  ... and ${diag.cisa_not_in_nvd_list.length - 10} more\n`;
        }
    }
    
    // Create modal or alert to display
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.7);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 10000;
    `;
    
    const content = document.createElement('div');
    content.style.cssText = `
        background: white;
        padding: 30px;
        border-radius: 10px;
        max-width: 800px;
        max-height: 80vh;
        overflow-y: auto;
        position: relative;
    `;
    
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕ Close';
    closeBtn.style.cssText = `
        position: absolute;
        top: 10px;
        right: 10px;
        padding: 5px 15px;
        background: #ff6b6b;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
    `;
    closeBtn.onclick = () => document.body.removeChild(modal);
    
    const pre = document.createElement('pre');
    pre.style.cssText = `
        font-family: monospace;
        white-space: pre-wrap;
        word-wrap: break-word;
        margin-top: 20px;
    `;
    pre.textContent = message;
    
    content.appendChild(closeBtn);
    content.appendChild(document.createElement('h2').appendChild(document.createTextNode('🔍 Diagnostics Results')).parentElement);
    content.appendChild(pre);
    modal.appendChild(content);
    document.body.appendChild(modal);
    
    // Also log to console
    console.log('Diagnostics Results:', diag);
}
