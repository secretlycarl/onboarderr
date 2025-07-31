// Navigation JavaScript - Loaded at end of body
console.log('Navigation script file loaded!');

document.addEventListener('DOMContentLoaded', function() {
  console.log('Navigation script starting...');
  
  const navToggle = document.getElementById('nav-toggle');
  const navMenu = document.getElementById('nav-menu');
  console.log('Navigation elements found:', {
    navToggle: !!navToggle,
    navMenu: !!navMenu
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
  
  console.log('Navigation script completed');
}); 