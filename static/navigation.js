// Navigation JavaScript - Loaded at end of body
console.log('Navigation script file loaded!');

document.addEventListener('DOMContentLoaded', function() {
  console.log('Navigation script starting...');
  
  const navToggle = document.getElementById('nav-toggle');
  const navMenu = document.getElementById('nav-menu');
  const adminLink = document.getElementById('admin-login-link');
  const mobileAdminLink = document.getElementById('mobile-admin-link');
  const modal = document.getElementById('admin-modal');
  const closeModal = document.getElementById('close-modal');
  const adminForm = document.getElementById('admin-login-form');
  const adminError = document.getElementById('admin-error');
  console.log('Navigation elements found:', {
    navToggle: !!navToggle,
    navMenu: !!navMenu,
    adminLink: !!adminLink,
    mobileAdminLink: !!mobileAdminLink,
    modal: !!modal
  });
  
  // Mobile navigation toggle
  if (navToggle && navMenu) {
    console.log('Setting up mobile navigation toggle');
    
    // Function to handle toggle
    function handleToggle(e) {
      console.log('Toggle triggered!');
      
      const isOpen = navMenu.classList.contains('open');
      console.log('Menu is currently open:', isOpen);
      
      navMenu.classList.toggle('open');
      navToggle.classList.toggle('active');
      
      console.log('Menu classes after toggle:', navMenu.className);
      console.log('Toggle classes after toggle:', navToggle.className);
      
      // Close menu when clicking outside
      if (!isOpen) {
        setTimeout(() => {
          document.addEventListener('click', closeMenuOnOutside);
          document.addEventListener('touchstart', closeMenuOnOutside);
        }, 0);
      } else {
        document.removeEventListener('click', closeMenuOnOutside);
        document.removeEventListener('touchstart', closeMenuOnOutside);
      }
    }
    
    // Add event listeners for both desktop and mobile
    navToggle.addEventListener('click', handleToggle);
    
    // Add touchstart for mobile devices
    navToggle.addEventListener('touchstart', function(e) {
      console.log('Touch event on nav toggle');
      e.preventDefault();
      e.stopPropagation();
      handleToggle(e);
    });
    
    function closeMenuOnOutside(e) {
      if (!navToggle.contains(e.target) && !navMenu.contains(e.target)) {
        navMenu.classList.remove('open');
        navToggle.classList.remove('active');
        document.removeEventListener('click', closeMenuOnOutside);
        document.removeEventListener('touchstart', closeMenuOnOutside);
      }
    }
  } else {
    console.error('Missing navigation elements:', {
      navToggle: !!navToggle,
      navMenu: !!navMenu
    });
  }
  
  // Admin modal functionality
  if (adminLink) {
    adminLink.addEventListener('click', function(e) {
      e.preventDefault();
      modal.style.display = 'flex';
      document.getElementById('admin-username').focus();
    });
  }
  
  if (mobileAdminLink) {
    mobileAdminLink.addEventListener('click', function(e) {
      e.preventDefault();
      modal.style.display = 'flex';
      document.getElementById('admin-username').focus();
    });
  }
  
  if (closeModal) {
    closeModal.addEventListener('click', function() {
      modal.style.display = 'none';
      adminError.textContent = '';
    });
  }
  
  if (modal) {
    modal.addEventListener('click', function(e) {
      if (e.target === modal) {
        modal.style.display = 'none';
        adminError.textContent = '';
      }
    });
  }
  
  if (adminForm) {
    adminForm.addEventListener('submit', function(e) {
      e.preventDefault();
      
      const formData = new FormData(adminForm);
      
      fetch('/admin-login', {
        method: 'POST',
        body: formData
      })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          window.location.reload();
        } else {
          adminError.textContent = data.error || 'Login failed';
        }
      })
      .catch(error => {
        console.error('Error:', error);
        adminError.textContent = 'An error occurred';
      });
    });
  }
  
  console.log('Navigation script completed');
}); 