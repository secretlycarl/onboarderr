// Carousel Auto-Scroll Implementation
// Based on old implementation but with modern improvements

class CarouselAutoScroll {
  constructor(carouselId, options = {}) {
    this.carousel = document.getElementById(carouselId);
    this.container = this.carousel?.parentElement;
    
    if (!this.carousel || !this.container) {
      console.error(`Carousel ${carouselId} not found`);
      return;
    }

    // Configuration
    this.options = {
      scrollSpeed: options.scrollSpeed || 0.5, // px per frame
      pauseOnHover: options.pauseOnHover !== false,
      pauseOnInteraction: options.pauseOnInteraction !== false,
      resumeDelay: options.resumeDelay || 1000, // ms after user interaction
      minPosters: options.minPosters || 8,
      loadMoreThreshold: options.loadMoreThreshold || 15,
      ...options
    };

    // State
    this.isPaused = false;
    this.isUserInteracting = false;
    this.offset = 0;
    this.lastLoadCheck = 0;
    this.isLoading = false;
    this.rafId = null;
    this.resumeTimeout = null;

    // Mobile detection
    this.isMobile = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    this.isDesktop = !this.isMobile && window.innerWidth > 768;

    // Touch interaction state
    this.isManualScrolling = false;
    this.manualScrollStartX = 0;
    this.manualScrollStartOffset = 0;
    this.touchStartTime = 0;
    this.lastTouchMoveTime = 0;

    // Scroll detection
    this.scrollTimeout = null;
    this.lastScrollLeft = 0;
    this.scrollStableCount = 0;

    this.init();
  }

  init() {
    console.log(`Initializing carousel auto-scroll for ${this.carousel.id}`);
    console.log('Device type:', this.isMobile ? 'Mobile' : 'Desktop');
    console.log('Configuration:', this.options);

    // Set up event listeners
    this.setupEventListeners();
    
    // Start animation
    this.startAnimation();
  }

  setupEventListeners() {
    // Touch events for mobile
    if (this.isMobile && this.options.pauseOnInteraction) {
      this.setupTouchEvents();
    }

    // Scroll detection for momentum scrolling
    if (this.isMobile) {
      this.setupScrollDetection();
    }
  }

  setupTouchEvents() {
    this.container.addEventListener('touchstart', (e) => {
      this.isUserInteracting = true;
      this.isManualScrolling = true;
      this.manualScrollStartX = e.touches[0].clientX;
      this.manualScrollStartOffset = this.offset;
      this.touchStartTime = Date.now();
      
      // Clear any existing resume timeout
      if (this.resumeTimeout) {
        clearTimeout(this.resumeTimeout);
        this.resumeTimeout = null;
      }
      
      console.log('Manual scroll started - auto-scroll paused');
    }, { passive: true });

    this.container.addEventListener('touchmove', (e) => {
      if (this.isManualScrolling) {
        const now = Date.now();
        // Throttle touch move events to reduce jumpiness - reduced from 16ms to 8ms for better fast scroll handling
        if (now - this.lastTouchMoveTime < 8) { // ~120fps for better fast scroll responsiveness
          return;
        }
        this.lastTouchMoveTime = now;
        
        const deltaX = e.touches[0].clientX - this.manualScrollStartX;
        let newOffset = this.manualScrollStartOffset + deltaX;
        
        // Prevent scrolling past available images
        const totalWidth = this.carousel.scrollWidth || this.carousel.offsetWidth;
        const containerWidth = this.container.offsetWidth;
        const maxScroll = Math.max(0, totalWidth - containerWidth);
        
        // Clamp the offset to prevent scrolling beyond available content
        newOffset = Math.max(-maxScroll, Math.min(0, newOffset));
        
        this.offset = newOffset;
        this.carousel.style.transform = `translateX(${this.offset}px)`;
      }
    }, { passive: true });

    this.container.addEventListener('touchend', (e) => {
      this.isManualScrolling = false;
      const touchDuration = Date.now() - this.touchStartTime;
      
      // Reset interaction flag after a delay to allow momentum to settle
      setTimeout(() => {
        this.isUserInteracting = false;
        console.log('Manual scroll ended - auto-scroll resumed');
        this.resumeAnimation();
      }, 300);
    }, { passive: true });
  }

  setupScrollDetection() {
    this.container.addEventListener('scroll', (e) => {
      const currentScrollLeft = this.container.scrollLeft;
      
      // Clear any existing timeout
      if (this.scrollTimeout) {
        clearTimeout(this.scrollTimeout);
      }
      
      // Check if scroll position has stabilized
      if (Math.abs(currentScrollLeft - this.lastScrollLeft) < 1) {
        this.scrollStableCount++;
      } else {
        this.scrollStableCount = 0;
      }
      
      this.lastScrollLeft = currentScrollLeft;
      
      // Set a timeout to detect when scrolling has completely stopped
      this.scrollTimeout = setTimeout(() => {
        // Only resume auto-scroll if scroll has been stable for multiple checks - reduced threshold for faster response
        if (this.scrollStableCount >= 2) { // Reduced from 3 to 2 for faster response
          this.isUserInteracting = false;
          console.log('Momentum scrolling ended - auto-scroll resumed');
          this.resumeAnimation();
        }
      }, 50); // Reduced from 100ms to 50ms for faster scroll detection
    }, { passive: true });
  }

  startAnimation() {
    console.log('Starting carousel animation');
    this.animate();
  }

  resumeAnimation() {
    // Clear any existing resume timeout
    if (this.resumeTimeout) {
      clearTimeout(this.resumeTimeout);
      this.resumeTimeout = null;
    }

    // Set a delay before resuming
    this.resumeTimeout = setTimeout(() => {
      this.isUserInteracting = false;
      console.log('Auto-scroll resumed after delay');
      // Force immediate animation frame to resume scrolling
      if (this.rafId) {
        cancelAnimationFrame(this.rafId);
      }
      this.rafId = requestAnimationFrame(() => this.animate());
    }, this.options.resumeDelay);
  }

  animate() {
    try {
      // Don't animate if there are no images or if we have a loading/error message
      if (this.carousel.children.length === 0 || this.carousel.querySelector('div')) {
        console.log('Animation skipped - no children or loading message');
        this.rafId = requestAnimationFrame(() => this.animate());
        return;
      }
      
      // Pause on hover or when user is manually scrolling
      if (!this.isPaused && !this.isUserInteracting) {
        // Check if we have enough images before scrolling
        if (this.carousel.children.length < 3) {
          console.log('Not enough images to scroll, pausing animation');
          this.rafId = requestAnimationFrame(() => this.animate());
          return;
        }
        
        this.offset -= this.options.scrollSpeed;
        this.carousel.style.transform = `translateX(${this.offset}px)`;
        
        // Remove images that have scrolled completely off screen, but maintain minimum
        const firstImg = this.carousel.children[0];
        if (firstImg && (firstImg.tagName === 'IMG' || firstImg.tagName === 'A') && this.carousel.children.length > 5) {
          const firstImgWidth = firstImg.offsetWidth + parseInt(getComputedStyle(this.carousel).gap || 0);
          if (Math.abs(this.offset) >= firstImgWidth) {
            // Don't remove images during user interaction to prevent conflicts
            if (!this.isUserInteracting) {
              firstImg.remove();
              this.offset += firstImgWidth;
              this.carousel.style.transform = `translateX(${this.offset}px)`;
              
              // Update width after removing image
              this.updateWidth();
              console.log('Removed image, remaining children:', this.carousel.children.length);
            }
          }
        }
        
        // Check if we need to load more posters (every 2 seconds as backup)
        const now = Date.now();
        if (now - this.lastLoadCheck > 2000) {
          this.lastLoadCheck = now;
          this.checkForMorePosters();
        }
      }
      
      this.rafId = requestAnimationFrame(() => this.animate());
    } catch (error) {
      console.error('Animation error:', error);
      // Stop animation on error
      if (this.rafId) {
        cancelAnimationFrame(this.rafId);
        this.rafId = null;
      }
    }
  }

  updateWidth() {
    if (this.carousel.children.length === 0) {
      return;
    }
    
    let totalWidth = 0;
    const gap = parseInt(getComputedStyle(this.carousel).gap || 0);
    
    Array.from(this.carousel.children).forEach((img, index) => {
      const imgWidth = img.offsetWidth;
      if (imgWidth === 0) {
        totalWidth += img.naturalWidth + gap;
      } else {
        totalWidth += imgWidth + gap;
      }
    });
    
    this.carousel.style.width = totalWidth + 'px';
  }

  checkForMorePosters() {
    if (this.options.onLoadMore && !this.isLoading) {
      const remainingImages = this.carousel.children.length;
      if (remainingImages <= this.options.loadMoreThreshold) {
        console.log(`Near end during auto-scroll - loading more posters quickly!`);
        this.isLoading = true;
        this.options.onLoadMore().then(() => {
          this.isLoading = false;
          console.log('Poster loading completed successfully');
        }).catch(error => {
          console.error('Error loading more posters:', error);
          this.isLoading = false;
          this.ensureMinimumPosters();
        });
      }
    }
  }

  ensureMinimumPosters() {
    const currentPosters = this.carousel.children.length;
    if (currentPosters < this.options.minPosters) {
      console.log(`Only ${currentPosters} posters left, adding more...`);
      if (this.options.onLoadMore) {
        this.options.onLoadMore().then(() => {
          console.log('Minimum posters ensured');
        }).catch(error => {
          console.error('Error ensuring minimum posters:', error);
        });
      }
    }
  }

  destroy() {
    if (this.rafId) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
    
    if (this.resumeTimeout) {
      clearTimeout(this.resumeTimeout);
      this.resumeTimeout = null;
    }
    
    if (this.scrollTimeout) {
      clearTimeout(this.scrollTimeout);
      this.scrollTimeout = null;
    }
    
    console.log('Carousel auto-scroll destroyed');
  }
}

// Global function to initialize carousel auto-scroll
window.initializeCarouselAutoScroll = function(carouselId, options = {}) {
  return new CarouselAutoScroll(carouselId, options);
}; 