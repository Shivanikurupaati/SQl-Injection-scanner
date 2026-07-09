function handleSignup(e) {
  e.preventDefault();
  const username = document.getElementById('username').value.trim();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const confirm = document.getElementById('confirmPassword').value;

  if (!username) { alert('Please enter a username'); return; }
  if (password.length < 6) { alert('Password should be at least 6 characters'); return; }
  if (password !== confirm) { alert('Passwords do not match'); return; }

  fetch('http://localhost:8000/api/v1/auth/signup', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ username, password })
  })
    .then(response => response.json().then(data => ({ status: response.status, body: data })))
    .then(({ status, body }) => {
      if (status === 200) {
        sessionStorage.setItem('signup_success', 'Account created successfully. Please log in.');
        window.location.href = 'login.html';
      } else {
        alert(body.detail || 'Signup failed');
      }
    })
    .catch(error => {
      console.error('Signup error:', error);
      alert('An error occurred during signup. Please ensure the backend is running.');
    });
}

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('signupForm');
  if (form) {
    form.addEventListener('submit', handleSignup);
  }
});
