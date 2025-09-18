// Basic JavaScript functionality

document.addEventListener('DOMContentLoaded', function () {
  // Toggle password visibility
  document.querySelectorAll('.toggle-password').forEach(button => {
    button.addEventListener('click', function () {
      const inputId = this.getAttribute('data-target');
      const input = document.getElementById(inputId);
      if (input.type === 'password') {
        input.type = 'text';
        this.innerHTML = '<i class="fas fa-eye-slash"></i>';
      } else {
        input.type = 'password';
        this.innerHTML = '<i class="fas fa-eye"></i>';
      }
    });
  });

  // Simple form validation can be added here

  // Alert auto-dismiss
  setTimeout(() => {
    document.querySelectorAll('.alert').forEach(alert => {
      if (alert.classList.contains('show')) {
        alert.classList.remove('show');
      }
    });
  }, 5000);
});
