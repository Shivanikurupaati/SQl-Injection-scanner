// Home page functionality

const DEFAULT_API_BASE = (window.APP_CONFIG && window.APP_CONFIG.apiBaseUrl) ||
    localStorage.getItem('sqlScannerApiBase') ||
    'http://localhost:8000';

const API_BASE_URL = DEFAULT_API_BASE.replace(/\/$/, '');
let urlsList = [];
let isGlobalScanInProgress = false;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function () {
    // Check auth
    const user = localStorage.getItem('sqlScannerUser');
    if (!user) {
        window.location.href = 'login.html';
        return;
    }

    loadURLsFromStorage();
    updateURLCount();
});

// Add URL to the list
function addURL() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();

    // Validation
    if (!url) {
        alert('Please enter a URL');
        return;
    }

    // Create URL object
    const urlObject = {
        id: Date.now(),
        url: url,
        dateAdded: new Date().toLocaleString(),
        status: 'pending',
        lastScan: null,
        result: null
    };

    // Add to list
    urlsList.push(urlObject);

    // Save to localStorage
    saveURLsToStorage();

    // Clear form
    clearForm();

    // Update display
    displayURLs();
    updateURLCount();

    alert('URL added successfully! Use "Scan" to analyze it.');
}

// Display URLs in the list
function displayURLs() {
    const urlsListElement = document.getElementById('urlsList');

    if (urlsList.length === 0) {
        urlsListElement.innerHTML = '<p class="empty-message">No URLs added yet. Add a URL above to get started.</p>';
        return;
    }

    let html = '';
    urlsList.forEach(item => {
        html += `
            <div class="url-item">
                <div class="url-info">
                    <div class="url-item-title">${escapeHtml(item.url)}</div>
                    <div class="url-item-description">
                        Added: ${item.dateAdded}
                        ${item.lastScan ? ` | Last Scan: ${item.lastScan}` : ' | Not scanned yet'}
                    </div>
                </div>
                <div class="url-status">
                    ${renderStatusBadge(item.status)}
                </div>
                <div class="url-actions">
                    <button class="btn-small btn-scan-single" onclick="scanSingleURL(${item.id}, this)" ${isGlobalScanInProgress ? 'disabled' : ''}>Scan</button>
                    <button class="btn-small btn-edit" onclick="editURL(${item.id})">Edit</button>
                    <button class="btn-small btn-delete" onclick="deleteURL(${item.id})">Delete</button>
                </div>
            </div>
        `;
    });

    urlsListElement.innerHTML = html;
}

// Delete URL from list
function deleteURL(id) {
    if (confirm('Are you sure you want to delete this URL?')) {
        urlsList = urlsList.filter(item => item.id !== id);
        saveURLsToStorage();
        displayURLs();
        updateURLCount();
        alert('URL deleted successfully!');
    }
}

// Edit URL
function editURL(id) {
    const item = urlsList.find(u => u.id === id);
    if (item) {
        document.getElementById('urlInput').value = item.url;
        deleteURL(id);
    }
}

// Clear form
function clearForm() {
    document.getElementById('urlInput').value = '';
}

// Clear all URLs
function clearAllURLs() {
    if (confirm('Are you sure you want to delete all URLs?')) {
        urlsList = [];
        saveURLsToStorage();
        displayURLs();
        updateURLCount();
        sessionStorage.removeItem('scanResults');
        alert('All URLs cleared!');
    }
}

// Scan all URLs
function scanAllURLs() {
    if (urlsList.length === 0) {
        alert('No URLs to scan. Please add some URLs first.');
        return;
    }

    if (isGlobalScanInProgress) {
        return;
    }

    const queries = urlsList.map(item => item.url);
    if (queries.length === 0) {
        alert('Nothing to scan.');
        return;
    }

    setGlobalScanState(true, `Scanning ${queries.length} URL(s)...`);

    fetch(`${API_BASE_URL}/api/v1/batch-detect`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            queries,
            log_to_db: true
        })
    })
        .then(async response => {
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText || 'Unexpected response from server.');
            }
            return response.json();
        })
        .then(data => {
            const scanTime = new Date();
            const transformedResults = (data.results || []).map((prediction, index) => {
                const statusPayload = mapPredictionToStatus(prediction);
                const urlItem = urlsList[index];

                if (urlItem) {
                    urlItem.status = statusPayload.status;
                    urlItem.lastScan = scanTime.toLocaleString();
                    urlItem.result = {
                        ...prediction,
                        ...statusPayload,
                        scannedAt: scanTime.toISOString()
                    };
                }

                return buildResultRecord(urlItem, prediction, statusPayload, scanTime, index);
            });

            saveURLsToStorage();
            displayURLs();

            sessionStorage.setItem('scanResults', JSON.stringify({
                generatedAt: scanTime.toISOString(),
                totalQueries: data.total_queries,
                injectionsDetected: data.injections_detected,
                results: transformedResults
            }));

            alert('Scan completed! Redirecting to results page.');
            window.location.href = 'results.html';
        })
        .catch(error => {
            console.error('Scan failed:', error);
            alert(`Failed to scan URLs. ${error.message || 'Please ensure the backend server is running.'}`);
        })
        .finally(() => {
            setGlobalScanState(false);
        });
}

// Update URL count
function updateURLCount() {
    document.getElementById('urlCount').textContent = urlsList.length;
}

// Save URLs to localStorage
function saveURLsToStorage() {
    localStorage.setItem('sqlScannerURLs', JSON.stringify(urlsList));
}

// Load URLs from localStorage
function loadURLsFromStorage() {
    const stored = localStorage.getItem('sqlScannerURLs');
    if (stored) {
        try {
            const parsed = JSON.parse(stored);
            urlsList = Array.isArray(parsed) ? parsed.map(item => ({
                ...item,
                status: item.status || 'pending',
                lastScan: item.lastScan || null,
                result: item.result || null
            })) : [];
        } catch (error) {
            console.warn('Failed to parse stored URLs:', error);
            urlsList = [];
        }
        displayURLs();
    }
}

// Logout function
function logout() {
    if (confirm('Are you sure you want to logout?')) {
        localStorage.removeItem('sqlScannerURLs');
        localStorage.removeItem('sqlScannerUser');
        sessionStorage.removeItem('scanResults');
        window.location.href = 'login.html';
    }
}

// Escape HTML special characters
function escapeHtml(text) {
    if (typeof text !== 'string') {
        return '';
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

function renderStatusBadge(status = 'pending') {
    const normalized = typeof status === 'string' ? status.toLowerCase() : 'pending';
    const labelMap = {
        pending: 'Pending',
        scanning: 'Scanning',
        safe: 'Safe',
        vulnerable: 'Vulnerable',
        warning: 'Warning',
        error: 'Error'
    };
    const label = labelMap[normalized] || status;
    return `<span class="status-badge status-${normalized}">${label}</span>`;
}

function setGlobalScanState(isScanning, loadingLabel = 'Scanning...') {
    isGlobalScanInProgress = isScanning;
    const scanAllButton = document.querySelector('.btn-scan');

    if (scanAllButton) {
        scanAllButton.disabled = isScanning;
        scanAllButton.textContent = isScanning ? loadingLabel : 'Scan All URLs';
    }

    const singleButtons = document.querySelectorAll('.btn-scan-single');
    singleButtons.forEach(button => {
        button.disabled = isScanning;
    });
}

async function scanSingleURL(id, buttonElement) {
    const urlItem = urlsList.find(item => item.id === id);
    if (!urlItem) {
        alert('URL not found.');
        return;
    }

    const button = buttonElement || null;
    if (button) {
        button.disabled = true;
        button.textContent = 'Scanning...';
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/v1/detect`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                query: urlItem.url,
                log_to_db: true
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || 'Unexpected response from server.');
        }

        const prediction = await response.json();
        const scanTime = new Date();
        const statusPayload = mapPredictionToStatus(prediction);

        urlItem.status = statusPayload.status;
        urlItem.lastScan = scanTime.toLocaleString();
        urlItem.result = {
            ...prediction,
            ...statusPayload,
            scannedAt: scanTime.toISOString()
        };

        saveURLsToStorage();
        displayURLs();

        const singleResultRecord = buildResultRecord(urlItem, prediction, statusPayload, scanTime, 0);
        sessionStorage.setItem('scanResults', JSON.stringify({
            generatedAt: scanTime.toISOString(),
            totalQueries: 1,
            injectionsDetected: prediction.is_sql_injection ? 1 : 0,
            results: [singleResultRecord]
        }));

        alert(`Scan complete! Status: ${statusPayload.status.toUpperCase()}. Open the Results page for details.`);
    } catch (error) {
        console.error('Single scan failed:', error);
        alert(`Failed to scan URL. ${error.message || 'Please ensure the backend server is running.'}`);
    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = 'Scan';
        }
    }
}

function mapPredictionToStatus(prediction) {
    const probabilityInjection = Number(prediction.probability_injection || 0);
    const confidence = Number(prediction.confidence || probabilityInjection || 0);
    const confidencePct = Math.round(confidence * 100);

    if (prediction.is_sql_injection) {
        return {
            status: 'vulnerable',
            severity: 'High',
            issuesFound: 3,
            description: `The model detected SQL injection characteristics. Confidence: ${confidencePct}%.`
        };
    }

    if (probabilityInjection >= 0.35) {
        return {
            status: 'warning',
            severity: 'Medium',
            issuesFound: 1,
            description: `Suspicious patterns detected (Injection probability ${(probabilityInjection * 100).toFixed(1)}%). Manual review recommended.`
        };
    }

    return {
        status: 'safe',
        severity: 'Low',
        issuesFound: 0,
        description: `No SQL injection characteristics detected. Confidence: ${confidencePct}%.`
    };
}

function buildResultRecord(urlItem, prediction, statusPayload, scanTime, index) {
    return {
        id: urlItem?.id || `${scanTime.getTime()}-${index}`,
        url: urlItem?.url || prediction.query,
        scanDate: scanTime.toLocaleString(),
        status: statusPayload.status,
        severity: statusPayload.severity,
        issuesFound: statusPayload.issuesFound,
        description: statusPayload.description,
        confidence: prediction.confidence,
        probabilitySafe: prediction.probability_safe,
        probabilityInjection: prediction.probability_injection,
        isSqlInjection: prediction.is_sql_injection,
        logId: prediction.log_id || null
    };
}
