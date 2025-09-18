// Security related JS: password strength, 2FA input handling

document.addEventListener('DOMContentLoaded', () => {
  const passwordField = document.getElementById('password');
  const confirmPasswordField = document.getElementById('confirm_password');
  const strengthBar = document.getElementById('strengthBar');
  const strengthText = document.getElementById('strengthText');

  function checkPasswordStrength(password) {
    let strength = 0;

    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;

    return strength;
  }

  function updateStrengthIndicator() {
    const password = passwordField.value;
    const strength = checkPasswordStrength(password);

    strengthBar.style.width = `${(strength / 5) * 100}%`;

    switch (strength) {
      case 0:
      case 1:
        strengthBar.className = 'progress-bar bg-danger';
        strengthText.textContent = 'Very Weak';
        break;
      case 2:
        strengthBar.className = 'progress-bar bg-warning';
        strengthText.textContent = 'Weak';
        break;
      case 3:
        strengthBar.className = 'progress-bar bg-info';
        strengthText.textContent = 'Fair';
        break;
      case 4:
        strengthBar.className = 'progress-bar bg-primary';
        strengthText.textContent = 'Strong';
        break;
      case 5:
        strengthBar.className = 'progress-bar bg-success';
        strengthText.textContent = 'Very Strong';
        break;
    }
  }

  if (passwordField) {
    passwordField.addEventListener('input', updateStrengthIndicator);
  }
});
