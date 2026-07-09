// Function to switch between pages
function showPage(pageId) {
    // Hide all pages
    const pages = document.querySelectorAll('.page');
    pages.forEach(page => {
        page.classList.remove('active');
    });

    // Show the selected page
    const selectedPage = document.getElementById(pageId);
    if (selectedPage) {
        selectedPage.classList.add('active');
    }
}

// Scanner functions
function scanQuery() {
    const query = document.getElementById('sqlInput').value;
    
    if (!query.trim()) {
        alert('Please enter a SQL query to scan.');
        return;
    }

    // Placeholder for backend integration later
    alert('Scan button clicked!\n\nQuery: ' + query);
    console.log('Scanning query:', query);
}

function clearInput() {
    document.getElementById('sqlInput').value = '';
}

// History functions
function clearHistory() {
    if (confirm('Are you sure you want to clear all scan history?')) {
        alert('History cleared!');
        console.log('History cleared');
    }
}

// Initialize - Show home page on load
document.addEventListener('DOMContentLoaded', function() {
    showPage('home');
    console.log('SQL Injection Scanner loaded successfully');
});
