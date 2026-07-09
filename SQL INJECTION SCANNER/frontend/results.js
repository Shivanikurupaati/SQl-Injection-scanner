// Results page functionality

const SCAN_RESULTS_STORAGE_KEY = 'scanResults';
let allResults = [];
let filteredResults = [];
let scanMetadata = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadResults();
});

// Load results from session storage or use sample data
function loadResults() {
    // Clean up deprecated storage key from earlier versions
    sessionStorage.removeItem('scannedURLs');

    const storedResults = sessionStorage.getItem(SCAN_RESULTS_STORAGE_KEY);

    if (storedResults) {
        try {
            scanMetadata = JSON.parse(storedResults);
            allResults = Array.isArray(scanMetadata.results) ? scanMetadata.results : [];
        } catch (error) {
            console.warn('Failed to parse stored scan results:', error);
            allResults = [];
        }
    } else {
        allResults = [];
    }

    filteredResults = [...allResults];
    updateSummary();
    displayResults();
}

// Display results
function displayResults() {
    const resultsContainer = document.getElementById('resultsContainer');

    if (filteredResults.length === 0) {
        resultsContainer.innerHTML = `
            <div class="empty-state">
                <p>No scan results available yet.</p>
                <p>${scanMetadata ? 'Try scanning again.' : 'Go to <a href="home.html">Home</a> and scan some URLs to see results here.'}</p>
            </div>
        `;
        return;
    }

    let html = '';
    filteredResults.forEach(result => {
        const statusClass = ((result.status || 'safe') + '').toLowerCase();
        const statusLabel = statusClass.charAt(0).toUpperCase() + statusClass.slice(1);
        html += `
            <div class="result-item ${statusClass}">
                <div class="result-header">
                    <div class="result-url">${escapeHtml(result.url)}</div>
                    <div class="result-status status-${statusClass}">${escapeHtml(statusLabel)}</div>
                </div>

                <div class="result-info">
                    <div class="info-item">
                        <div class="info-label">Scan Date</div>
                        <div class="info-value">${result.scanDate}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Issues Found</div>
                        <div class="info-value">${result.issuesFound}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Vulnerability Type</div>
                        <div class="info-value">${escapeHtml(result.isSqlInjection ? 'SQL Injection' : (result.status === 'warning' ? 'Potential SQL Injection' : 'None'))}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Severity</div>
                        <div class="info-value">${escapeHtml(result.severity)}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Confidence</div>
                        <div class="info-value">${formatPercent(result.confidence)}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Injection Probability</div>
                        <div class="info-value">${formatPercent(result.probabilityInjection)}</div>
                    </div>
                </div>

                <div class="result-description">
                    ${escapeHtml(result.description)}
                </div>

                <div class="result-actions">
                    <button class="btn-small btn-view" onclick="showDetails(${result.id})">View Details</button>
                    <button class="btn-small btn-download" onclick="downloadReport(${result.id})">Download Report</button>
                </div>
            </div>
        `;
    });

    resultsContainer.innerHTML = html;
}

// Filter results
function filterResults() {
    const filterValue = document.getElementById('filterStatus').value;

    if (filterValue === '') {
        filteredResults = [...allResults];
    } else {
        filteredResults = allResults.filter(result => {
            const status = typeof result.status === 'string' ? result.status.toLowerCase() : '';
            return status === filterValue;
        });
    }

    displayResults();
}

// Show details in modal
function showDetails(id) {
    const result = allResults.find(r => r.id === id);
    if (!result) return;

    const modalBody = document.getElementById('modalBody');
    modalBody.innerHTML = `
        <p><strong>URL:</strong> ${escapeHtml(result.url)}</p>
        <p><strong>Scan Date:</strong> ${result.scanDate}</p>
        <p><strong>Status:</strong> ${escapeHtml(result.status)}</p>
        <p><strong>Severity:</strong> ${escapeHtml(result.severity)}</p>
        <p><strong>Confidence:</strong> ${formatPercent(result.confidence)}</p>
        <p><strong>Injection Probability:</strong> ${formatPercent(result.probabilityInjection)}</p>
        ${result.logId ? `<p><strong>Log ID:</strong> ${result.logId}</p>` : ''}
        <h4>Vulnerability Details</h4>
        <p>${escapeHtml(result.description)}</p>
        <h4>Recommendations</h4>
        <ul>
            <li>Use parameterized queries or prepared statements</li>
            <li>Implement input validation and sanitization</li>
            <li>Apply ORM frameworks when possible</li>
            <li>Apply principle of least privilege to database accounts</li>
            <li>Enable SQL error message suppression in production</li>
        </ul>
    `;

    document.getElementById('detailsModal').classList.add('show');
}

// Close modal
function closeModal() {
    document.getElementById('detailsModal').classList.remove('show');
}

// Download report
function downloadReport(id) {
    const result = allResults.find(r => r.id === id);
    if (!result) return;

    const reportContent = `
SQL INJECTION SCANNER - REPORT
==============================

URL: ${result.url}
Scan Date: ${result.scanDate}
Status: ${result.status}
Severity: ${result.severity}
Issues Found: ${result.issuesFound}
Confidence: ${formatPercent(result.confidence)}
Injection Probability: ${formatPercent(result.probabilityInjection)}
Log ID: ${result.logId || 'N/A'}

VULNERABILITY DETAILS:
${result.description}

RECOMMENDATIONS:
1. Use parameterized queries or prepared statements
2. Implement input validation and sanitization
3. Use ORM frameworks when possible
4. Apply principle of least privilege to database accounts
5. Enable SQL error message suppression in production

Report Generated: ${new Date().toLocaleString()}
    `;

    const blob = new Blob([reportContent], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SQL_Injection_Report_${result.id}.txt`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);

    alert('Report downloaded successfully!');
}

// Export all results
function exportResults() {
    if (allResults.length === 0) {
        alert('No results to export');
        return;
    }

    let exportContent = 'URL,Status,Issues Found,Severity,Confidence,Injection Probability,Scan Date,Log ID\n';
    
    allResults.forEach(result => {
        exportContent += `"${result.url}","${result.status}",${result.issuesFound},"${result.severity}","${formatPercent(result.confidence)}","${formatPercent(result.probabilityInjection)}","${result.scanDate}",${result.logId || ''}\n`;
    });

    const blob = new Blob([exportContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SQL_Injection_Results_${new Date().getTime()}.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);

    alert('Results exported successfully!');
}

// Go home
function goHome() {
    window.location.href = 'home.html';
}

// Logout function
function logout() {
    if (confirm('Are you sure you want to logout?')) {
        sessionStorage.removeItem('scannedURLs');
        window.location.href = 'login.html';
    }
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('detailsModal');
    if (event.target == modal) {
        modal.classList.remove('show');
    }
}

// Escape HTML special characters
function escapeHtml(text) {
    if (typeof text !== 'string') {
        return text;
    }
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function formatPercent(value) {
    if (value === null || value === undefined || isNaN(Number(value))) {
        return 'N/A';
    }
    return `${(Number(value) * 100).toFixed(2)}%`;
}

function updateSummary() {
    const summaryParagraph = document.querySelector('.results-header p');
    if (!summaryParagraph) {
        return;
    }

    if (!scanMetadata) {
        summaryParagraph.textContent = 'Detailed vulnerability analysis for your scanned URLs';
        return;
    }

    const total = scanMetadata.totalQueries ?? allResults.length;
    const detected = scanMetadata.injectionsDetected ?? allResults.filter(r => r.isSqlInjection).length;
    const generatedAt = scanMetadata.generatedAt ? new Date(scanMetadata.generatedAt).toLocaleString() : 'N/A';

    summaryParagraph.textContent = `Last scan: ${generatedAt} • URLs scanned: ${total} • Injections detected: ${detected}`;
}
