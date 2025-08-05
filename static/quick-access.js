// Quick Access Panel Toggle Functionality
document.addEventListener('DOMContentLoaded', () => {
  const quickAccessPanel = document.getElementById('quickAccessPanel');
  const quickAccessToggle = document.getElementById('quickAccessToggle');
  const quickAccessTitleToggle = document.getElementById('quickAccessTitleToggle');
  
  if (!quickAccessPanel || !quickAccessToggle) {
    return; // Exit if elements don't exist
  }

  // Check if we're on desktop (quick access panel is hidden on mobile)
  const isDesktop = window.matchMedia('(min-width: 1025px)').matches;
  
  if (!isDesktop) {
    return; // Exit if not desktop
  }

  // Load saved state from localStorage
  const savedState = localStorage.getItem('quickAccessMinimized');
  if (savedState === 'true') {
    quickAccessPanel.classList.add('minimized');
  }

  const handleToggle = () => {
    const isMinimized = quickAccessPanel.classList.contains('minimized');
    
    if (isMinimized) {
      // Expand the panel
      quickAccessPanel.classList.remove('minimized');
      localStorage.setItem('quickAccessMinimized', 'false');
    } else {
      // Minimize the panel
      quickAccessPanel.classList.add('minimized');
      localStorage.setItem('quickAccessMinimized', 'true');
    }
  };

  // Add click event listener to the main toggle
  quickAccessToggle.addEventListener('click', handleToggle);
  
  // Add click event listener to the title toggle
  if (quickAccessTitleToggle) {
    quickAccessTitleToggle.addEventListener('click', handleToggle);
  }
  
  // Add keyboard support for accessibility
  quickAccessToggle.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      handleToggle();
    }
  });

  // Add keyboard support for title toggle
  if (quickAccessTitleToggle) {
    quickAccessTitleToggle.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        handleToggle();
      }
    });
  }

  // Add focus styles for better accessibility
  quickAccessToggle.setAttribute('tabindex', '0');
  quickAccessToggle.setAttribute('role', 'button');
  quickAccessToggle.setAttribute('aria-label', 'Toggle Quick Access Panel');

  if (quickAccessTitleToggle) {
    quickAccessTitleToggle.setAttribute('tabindex', '0');
    quickAccessTitleToggle.setAttribute('role', 'button');
  }

  // Handle window resize to ensure proper state
  window.addEventListener('resize', () => {
    const isDesktop = window.matchMedia('(min-width: 1025px)').matches;
    if (!isDesktop && quickAccessPanel.classList.contains('minimized')) {
      // If switching to mobile, expand the panel
      quickAccessPanel.classList.remove('minimized');
    }
  });

  // Add a small delay to prevent accidental clicks during page load
  let isInitialized = false;
  setTimeout(() => {
    isInitialized = true;
  }, 500);

  // Prevent accidental clicks during page load
  quickAccessToggle.addEventListener('click', (event) => {
    if (!isInitialized) {
      event.preventDefault();
      return;
    }
  }, { once: true });

  if (quickAccessTitleToggle) {
    quickAccessTitleToggle.addEventListener('click', (event) => {
      if (!isInitialized) {
        event.preventDefault();
        return;
      }
    }, { once: true });
  }
}); 