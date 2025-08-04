// Smooth Background Extension System
// Handles background gradient extension when details sections open/close and on scroll

class SmoothBackgroundExtension {
  constructor() {
    this.body = document.body;
    this.isExtended = false;
    this.scrollThreshold = 200; // pixels from bottom to start extension
    this.detailsObserver = null;
    this.scrollHandler = null;
    this.lastDocumentHeight = 0;
    this.extensionProgress = 0;
    
    this.init();
  }

  init() {
    // Set up mutation observer for details sections
    this.setupDetailsObserver();
    
    // Set up scroll handler
    this.setupScrollHandler();
    
    // Initial check
    this.checkBackgroundExtension();
  }

  setupDetailsObserver() {
    // Watch for details sections opening/closing
    this.detailsObserver = new MutationObserver((mutations) => {
      let shouldCheck = false;
      
      mutations.forEach((mutation) => {
        if (mutation.type === 'attributes' && mutation.attributeName === 'open') {
          shouldCheck = true;
        }
      });
      
      if (shouldCheck) {
        // Small delay to allow DOM to update
        setTimeout(() => {
          this.lastDocumentHeight = document.documentElement.scrollHeight;
          this.checkBackgroundExtension();
        }, 150);
      }
    });

    // Observe all details elements
    const detailsElements = document.querySelectorAll('details.collapsible-section');
    detailsElements.forEach(details => {
      this.detailsObserver.observe(details, {
        attributes: true,
        attributeFilter: ['open']
      });
    });
  }

  setupScrollHandler() {
    this.scrollHandler = this.handleScroll.bind(this);
    window.addEventListener('scroll', this.scrollHandler, { passive: true });
  }

  handleScroll() {
    // Throttle scroll events for performance
    if (this.scrollTimeout) {
      clearTimeout(this.scrollTimeout);
    }
    
    this.scrollTimeout = setTimeout(() => {
      this.checkBackgroundExtension();
    }, 16); // ~60fps
  }

  checkBackgroundExtension() {
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    const windowHeight = window.innerHeight;
    const documentHeight = document.documentElement.scrollHeight;
    const scrollBottom = scrollTop + windowHeight;
    
    // Calculate how close we are to the bottom
    const distanceFromBottom = documentHeight - scrollBottom;
    
    if (distanceFromBottom <= this.scrollThreshold) {
      // We're within the threshold, calculate extension progress
      const progress = Math.max(0, Math.min(1, (this.scrollThreshold - distanceFromBottom) / this.scrollThreshold));
      this.setBackgroundExtension(true, progress);
    } else {
      // We're not near the bottom, hide extension
      this.setBackgroundExtension(false, 0);
    }
  }

  setBackgroundExtension(extend, progress = 0) {
    const shouldExtend = extend && progress > 0;
    
    if (shouldExtend !== this.isExtended || Math.abs(progress - this.extensionProgress) > 0.01) {
      this.isExtended = shouldExtend;
      this.extensionProgress = progress;
      
      if (shouldExtend) {
        this.body.classList.add('background-extended');
        // Set custom property for gradual opacity
        this.body.style.setProperty('--bg-extension-opacity', progress.toString());
      } else {
        this.body.classList.remove('background-extended');
        this.body.style.removeProperty('--bg-extension-opacity');
      }
    }
  }

  destroy() {
    if (this.detailsObserver) {
      this.detailsObserver.disconnect();
    }
    
    if (this.scrollHandler) {
      window.removeEventListener('scroll', this.scrollHandler);
    }
    
    if (this.scrollTimeout) {
      clearTimeout(this.scrollTimeout);
    }
  }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.smoothBackgroundExtension = new SmoothBackgroundExtension();
}); 