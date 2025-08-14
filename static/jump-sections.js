// Jump Sections Panel Toggle Functionality
document.addEventListener('DOMContentLoaded', () => {
  const jumpSectionsPanel = document.getElementById('jumpSectionsPanel');
  const jumpSectionsToggle = document.getElementById('jumpSectionsToggle');
  const jumpSectionsTitleToggle = document.getElementById('jumpSectionsTitleToggle');
  
  if (!jumpSectionsPanel || !jumpSectionsToggle) {
    return; // Exit if elements don't exist
  }

  // Check if we're on desktop (jump sections panel is hidden on mobile)
  const isDesktop = window.matchMedia('(min-width: 1025px)').matches;
  
  if (!isDesktop) {
    return; // Exit if not desktop
  }

  // Load saved state from localStorage
  const savedState = localStorage.getItem('jumpSectionsMinimized');
  if (savedState === 'true') {
    jumpSectionsPanel.classList.add('minimized');
  }

  const handleToggle = () => {
    const isMinimized = jumpSectionsPanel.classList.contains('minimized');
    
    if (isMinimized) {
      // Expand the panel
      jumpSectionsPanel.classList.remove('minimized');
      localStorage.setItem('jumpSectionsMinimized', 'false');
    } else {
      // Minimize the panel
      jumpSectionsPanel.classList.add('minimized');
      localStorage.setItem('jumpSectionsMinimized', 'true');
    }
  };

  // Add click event listener to the main toggle
  jumpSectionsToggle.addEventListener('click', handleToggle);
  
  // Add click event listener to the title toggle
  if (jumpSectionsTitleToggle) {
    jumpSectionsTitleToggle.addEventListener('click', handleToggle);
  }
  
  // Add keyboard support for accessibility
  jumpSectionsToggle.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      handleToggle();
    }
  });

  // Add keyboard support for title toggle
  if (jumpSectionsTitleToggle) {
    jumpSectionsTitleToggle.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        handleToggle();
      }
    });
  }

  // Add focus styles for better accessibility
  jumpSectionsToggle.setAttribute('tabindex', '0');
  jumpSectionsToggle.setAttribute('role', 'button');
  jumpSectionsToggle.setAttribute('aria-label', 'Toggle Jump to Sections Panel');

  if (jumpSectionsTitleToggle) {
    jumpSectionsTitleToggle.setAttribute('tabindex', '0');
    jumpSectionsTitleToggle.setAttribute('role', 'button');
  }

  // Handle window resize to ensure proper state
  let resizeTimeout;
  window.addEventListener('resize', () => {
    // Debounce resize events to prevent excessive calls
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => {
      const isDesktop = window.matchMedia('(min-width: 1025px)').matches;
      if (!isDesktop && jumpSectionsPanel.classList.contains('minimized')) {
        // If switching to mobile, expand the panel
        jumpSectionsPanel.classList.remove('minimized');
      }
      // Ensure panel is visible on desktop after resize
      if (isDesktop && !jumpSectionsPanel.classList.contains('minimized')) {
        // Force a reflow to ensure proper rendering
        jumpSectionsPanel.offsetHeight;
      }
    }, 100);
  });

  // Add a small delay to prevent accidental clicks during page load
  let isInitialized = false;
  setTimeout(() => {
    isInitialized = true;
  }, 300); // Reduced from 500ms to 300ms

  // Prevent accidental clicks during page load (without removing the listener)
  const handleInitialClick = (event) => {
    if (!isInitialized) {
      event.preventDefault();
      return;
    }
    // Remove this wrapper once initialized
    jumpSectionsToggle.removeEventListener('click', handleInitialClick);
    if (jumpSectionsTitleToggle) {
      jumpSectionsTitleToggle.removeEventListener('click', handleInitialClick);
    }
  };

  jumpSectionsToggle.addEventListener('click', handleInitialClick);
  if (jumpSectionsTitleToggle) {
    jumpSectionsTitleToggle.addEventListener('click', handleInitialClick);
  }

  // Fallback mechanism: Add a global click handler as backup
  let fallbackClickCount = 0;
  const fallbackClickHandler = (event) => {
    // Only trigger if clicking on the panel area and no other handlers worked
    if (event.target.closest('.jump-sections-panel') && 
        !event.target.closest('.jump-sections-toggle') && 
        !event.target.closest('.jump-sections-title-toggle')) {
      fallbackClickCount++;
      if (fallbackClickCount >= 3) { // After 3 clicks, force toggle
        handleToggle();
        fallbackClickCount = 0;
      }
    } else {
      fallbackClickCount = 0;
    }
  };

  // Add fallback handler after a delay
  setTimeout(() => {
    document.addEventListener('click', fallbackClickHandler);
  }, 1000);

  // Emergency reset function (can be called from console)
  window.resetJumpSectionsPanel = () => {
    jumpSectionsPanel.classList.remove('minimized');
    localStorage.setItem('jumpSectionsMinimized', 'false');
    console.log('Jump sections panel reset');
  };
}); 