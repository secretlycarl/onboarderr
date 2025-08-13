// Navigation JavaScript - Loaded at end of body
// Navigation script loaded - debug logging controlled by debug-utils.js

/**
 * Detects if the device is a mobile phone or tablet based on a combination of
 * touch capability, pointer type, screen width, and user agent string.
 */
function isMobileDevice() {
  const hasCoarsePointer = window.matchMedia('(pointer: coarse)').matches;
  const screenWidth = window.innerWidth;
  
  // Rule 1: Most reliable. A device is mobile if it has a touch pointer AND is not wide.
  // This correctly excludes touchscreen laptops which are wide.
  if (hasCoarsePointer && screenWidth < 1024) {
    return true;
  }

  // Rule 2: Fallback using user agent sniffing for common mobile keywords.
  const userAgent = navigator.userAgent.toLowerCase();
  if (/mobi|android|iphone|ipad|ipod/.test(userAgent)) {
    return true;
  }
  
  // If neither rule matches, it's likely a desktop or laptop.
  return false;
}

// Ensure the body class is set on page load
document.addEventListener('DOMContentLoaded', function() {
    if (isMobileDevice()) {
        document.body.classList.add('mobile-device');
        document.body.classList.remove('desktop-device');
    } else {
        document.body.classList.add('desktop-device');
        document.body.classList.remove('mobile-device');
    }
});

// Set mobile/desktop classes on body element
function setDeviceClasses() {
  const isMobile = isMobileDevice();
  
  if (isMobile) {
    document.body.classList.add('mobile-device');
    document.body.classList.remove('desktop-device');
  } else {
    document.body.classList.add('desktop-device');
    document.body.classList.remove('mobile-device');
  }
  
  if (window.debugLog) {
    window.debugLog('Device detection - Mobile:', isMobile);
    window.debugLog('Screen width:', window.innerWidth);
    window.debugLog('Screen height:', window.innerHeight);
    window.debugLog('Pointer type:', window.matchMedia('(pointer: coarse)').matches);
    window.debugLog('Touch support:', 'ontouchstart' in window);
    window.debugLog('Max touch points:', navigator.maxTouchPoints);
    window.debugLog('User agent:', navigator.userAgent);
  }
}

document.addEventListener('DOMContentLoaded', function() {
  if (window.debugLog) {
    window.debugLog('Navigation script starting...');
  }
  
  // Set device classes early
  setDeviceClasses();
  
  const navToggle = document.getElementById('nav-toggle');
  const navMenu = document.getElementById('nav-menu');
  const navHeader = document.querySelector('.nav-mobile-header');
  if (window.debugLog) {
    window.debugLog('Navigation elements found:', {
      navToggle: !!navToggle,
      navMenu: !!navMenu,
      navHeader: !!navHeader
    });
  }
  
  // Mobile navigation toggle
  if (navToggle && navMenu && navHeader) {
    if (window.debugLog) {
      window.debugLog('Setting up mobile navigation toggle');
    }
    
    // Function to handle toggle
    function handleToggle(e) {
      if (window.debugLog) {
        window.debugLog('Toggle triggered!');
      }
      
      const isOpen = navMenu.classList.contains('open');
      if (window.debugLog) {
        window.debugLog('Menu is currently open:', isOpen);
      }
      
      navMenu.classList.toggle('open');
      navToggle.classList.toggle('active');
      
      if (window.debugLog) {
        window.debugLog('Menu classes after toggle:', navMenu.className);
        window.debugLog('Toggle classes after toggle:', navToggle.className);
      }
      
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
    
    // Add event listeners for the entire header (mobile-friendly)
    navHeader.addEventListener('click', handleToggle);
    
    // Add touchstart for mobile devices on the header
    navHeader.addEventListener('touchstart', function(e) {
      if (window.debugLog) {
        window.debugLog('Touch event on nav header');
      }
      e.preventDefault();
      e.stopPropagation();
      handleToggle(e);
    });
    
    // Keep the original toggle button listeners for accessibility
    navToggle.addEventListener('click', function(e) {
      e.stopPropagation(); // Prevent double-triggering
      handleToggle(e);
    });
    
    navToggle.addEventListener('touchstart', function(e) {
      if (window.debugLog) {
        window.debugLog('Touch event on nav toggle');
      }
      e.preventDefault();
      e.stopPropagation();
      handleToggle(e);
    });
    
    function closeMenuOnOutside(e) {
      if (!navHeader.contains(e.target) && !navMenu.contains(e.target)) {
        navMenu.classList.remove('open');
        navToggle.classList.remove('active');
        document.removeEventListener('click', closeMenuOnOutside);
        document.removeEventListener('touchstart', closeMenuOnOutside);
      }
    }
  } else {
    if (window.debugError) {
      window.debugError('Missing navigation elements:', {
        navToggle: !!navToggle,
        navMenu: !!navMenu,
        navHeader: !!navHeader
      });
    }
  }
  
  if (window.debugLog) {
    window.debugLog('Navigation script completed');
  }
}); 