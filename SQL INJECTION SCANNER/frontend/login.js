// Login page functionality

function handleLogin(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const remember = document.getElementById('remember').checked;

    // Validation
    if (!username || !password) {
        alert('Please fill in all fields');
        return;
    }

    fetch('http://localhost:8000/api/v1/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    })
        .then(response => response.json().then(data => ({ status: response.status, body: data })))
        .then(({ status, body }) => {
            if (status === 200) {
                // Store login info
                const userData = {
                    username: body.username,
                    token: body.token
                };
                localStorage.setItem('sqlScannerUser', JSON.stringify(userData));

                if (remember) {
                    localStorage.setItem('username', username);
                }

                alert('Login successful!\nWelcome ' + body.username);
                window.location.href = 'home.html';
            } else {
                alert(body.detail || 'Login failed');
            }
        })
        .catch(error => {
            console.error('Login error:', error);
            alert('An error occurred during login. Please ensure the backend is running.');
        });
}

// Auto-fill username if it was saved
document.addEventListener('DOMContentLoaded', function () {
    const savedUsername = localStorage.getItem('username');
    if (savedUsername) {
        document.getElementById('username').value = savedUsername;
        document.getElementById('remember').checked = true;
    }

    // Attach event listener
    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', handleLogin);
    }
});
