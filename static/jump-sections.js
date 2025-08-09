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
  window.addEventListener('resize', () => {
    const isDesktop = window.matchMedia('(min-width: 1025px)').matches;
    if (!isDesktop && jumpSectionsPanel.classList.contains('minimized')) {
      // If switching to mobile, expand the panel
      jumpSectionsPanel.classList.remove('minimized');
    }
  });

  // Add a small delay to prevent accidental clicks during page load
  let isInitialized = false;
  setTimeout(() => {
    isInitialized = true;
  }, 500);

  // Prevent accidental clicks during page load
  jumpSectionsToggle.addEventListener('click', (event) => {
    if (!isInitialized) {
      event.preventDefault();
      return;
    }
  }, { once: true });

  if (jumpSectionsTitleToggle) {
    jumpSectionsTitleToggle.addEventListener('click', (event) => {
      if (!isInitialized) {
        event.preventDefault();
        return;
      }
    }, { once: true });
  }
}); 