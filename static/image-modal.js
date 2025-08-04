// Image Modal System
class ImageModal {
  constructor() {
    this.modal = null;
    this.currentImage = null;
    this.touchStartX = 0;
    this.touchStartY = 0;
    this.zoomLevel = 1;
    this.minZoom = 1;
    this.maxZoom = 3;
    this.isZoomed = false;
    this.panX = 0;
    this.panY = 0;
    this.lastTouchDistance = 0;
    this.lastTouchCenterX = 0;
    this.lastTouchCenterY = 0;
    this.init();
  }

  init() {
    // Create modal HTML
    this.createModal();
    
    // Add event listeners
    this.addEventListeners();
    
    // Initialize clickable images
    this.initClickableImages();
  }

  createModal() {
    this.modal = document.createElement('div');
    this.modal.className = 'image-modal';
    this.modal.setAttribute('role', 'dialog');
    this.modal.setAttribute('aria-modal', 'true');
    this.modal.setAttribute('aria-label', 'Image viewer');
    this.modal.innerHTML = `
      <div class="image-modal-content">
        <button class="image-modal-close" aria-label="Close image viewer">×</button>
        <div class="image-modal-zoom-container">
          <img src="" alt="Enlarged image">
        </div>
      </div>
    `;
    document.body.appendChild(this.modal);
  }

  addEventListeners() {
    // Close modal on close button click
    const closeBtn = this.modal.querySelector('.image-modal-close');
    closeBtn.addEventListener('click', () => this.close());

    // Close modal on background click
    this.modal.addEventListener('click', (e) => {
      if (e.target === this.modal) {
        this.close();
      }
    });

    // Close modal on escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.modal.classList.contains('open')) {
        this.close();
      }
    });

    // Prevent body scroll when modal is open
    this.modal.addEventListener('transitionend', () => {
      if (this.modal.classList.contains('open')) {
        document.body.style.overflow = 'hidden';
      } else {
        document.body.style.overflow = '';
      }
    });

    // Touch/swipe gestures for mobile
    this.addTouchGestures();
  }

  addTouchGestures() {
    let startX = 0;
    let startY = 0;
    let currentX = 0;
    let currentY = 0;
    let touchCount = 0;
    let lastTapTime = 0;
    let tapCount = 0;

    this.modal.addEventListener('touchstart', (e) => {
      touchCount = e.touches.length;
      
      if (touchCount === 1) {
        // Single touch - handle pan and swipe to close
        startX = e.touches[0].clientX;
        startY = e.touches[0].clientY;
        currentX = startX;
        currentY = startY;
        
        // Handle double tap to reset zoom
        const currentTime = new Date().getTime();
        const timeDiff = currentTime - lastTapTime;
        
        if (timeDiff < 300 && timeDiff > 0) {
          // Double tap detected
          tapCount = 0;
          lastTapTime = 0;
          this.resetZoom();
        } else {
          tapCount++;
          lastTapTime = currentTime;
        }
      } else if (touchCount === 2) {
        // Two finger touch - handle pinch to zoom
        this.handlePinchStart(e);
      }
    }, { passive: true });

    this.modal.addEventListener('touchmove', (e) => {
      touchCount = e.touches.length;
      
      if (touchCount === 1 && !this.isZoomed) {
        // Single touch when not zoomed - handle swipe to close
        if (!startX || !startY) return;
        
        e.preventDefault();
        currentX = e.touches[0].clientX;
        currentY = e.touches[0].clientY;
        
        const deltaX = currentX - startX;
        const deltaY = currentY - startY;
        
        // If horizontal swipe is more significant than vertical, close on swipe
        if (Math.abs(deltaX) > Math.abs(deltaY) && Math.abs(deltaX) > 50) {
          this.close();
          startX = startY = 0;
        }
      } else if (touchCount === 2) {
        // Two finger touch - handle pinch to zoom
        e.preventDefault();
        this.handlePinchMove(e);
      } else if (touchCount === 1 && this.isZoomed) {
        // Single touch when zoomed - handle pan
        e.preventDefault();
        this.handlePan(e);
      }
    }, { passive: false });

    this.modal.addEventListener('touchend', (e) => {
      if (e.touches.length === 0) {
        // All touches ended
        startX = startY = 0;
        this.lastTouchDistance = 0;
        this.lastTouchCenterX = 0;
        this.lastTouchCenterY = 0;
      }
    }, { passive: true });
  }

  handlePinchStart(e) {
    const touch1 = e.touches[0];
    const touch2 = e.touches[1];
    
    this.lastTouchDistance = this.getTouchDistance(touch1, touch2);
    this.lastTouchCenterX = (touch1.clientX + touch2.clientX) / 2;
    this.lastTouchCenterY = (touch1.clientY + touch2.clientY) / 2;
  }

  handlePinchMove(e) {
    const touch1 = e.touches[0];
    const touch2 = e.touches[1];
    
    const currentDistance = this.getTouchDistance(touch1, touch2);
    const currentCenterX = (touch1.clientX + touch2.clientX) / 2;
    const currentCenterY = (touch1.clientY + touch2.clientY) / 2;
    
    if (this.lastTouchDistance > 0) {
      // Calculate zoom
      const scale = currentDistance / this.lastTouchDistance;
      const newZoom = Math.max(this.minZoom, Math.min(this.maxZoom, this.zoomLevel * scale));
      
      // Calculate zoom center relative to the container
      const zoomContainer = this.modal.querySelector('.image-modal-zoom-container');
      const rect = zoomContainer.getBoundingClientRect();
      const centerX = currentCenterX - rect.left;
      const centerY = currentCenterY - rect.top;
      
      // Update zoom and pan
      this.setZoom(newZoom, centerX, centerY);
    }
    
    this.lastTouchDistance = currentDistance;
    this.lastTouchCenterX = currentCenterX;
    this.lastTouchCenterY = currentCenterY;
  }

  handlePan(e) {
    const touch = e.touches[0];
    
    // If this is the first pan move, initialize the last position
    if (this.lastTouchCenterX === 0 && this.lastTouchCenterY === 0) {
      this.lastTouchCenterX = touch.clientX;
      this.lastTouchCenterY = touch.clientY;
      return;
    }
    
    const deltaX = touch.clientX - this.lastTouchCenterX;
    const deltaY = touch.clientY - this.lastTouchCenterY;
    
    this.panX += deltaX;
    this.panY += deltaY;
    
    this.lastTouchCenterX = touch.clientX;
    this.lastTouchCenterY = touch.clientY;
    
    this.updateImageTransform();
  }

  getTouchDistance(touch1, touch2) {
    const dx = touch1.clientX - touch2.clientX;
    const dy = touch1.clientY - touch2.clientY;
    return Math.sqrt(dx * dx + dy * dy);
  }

  setZoom(zoom, centerX = null, centerY = null) {
    const oldZoom = this.zoomLevel;
    this.zoomLevel = zoom;
    this.isZoomed = zoom > 1;
    
    if (centerX !== null && centerY !== null) {
      // Calculate the touch point relative to the image center
      const img = this.modal.querySelector('img');
      const zoomContainer = this.modal.querySelector('.image-modal-zoom-container');
      const containerRect = zoomContainer.getBoundingClientRect();
      
      // Convert touch coordinates to be relative to the container center
      const containerCenterX = containerRect.width / 2;
      const containerCenterY = containerRect.height / 2;
      const touchOffsetX = centerX - containerCenterX;
      const touchOffsetY = centerY - containerCenterY;
      
      // Calculate how much the pan should change to keep the touch point in the same relative position
      const zoomRatio = zoom / oldZoom;
      this.panX = touchOffsetX - (touchOffsetX - this.panX) * zoomRatio;
      this.panY = touchOffsetY - (touchOffsetY - this.panY) * zoomRatio;
    }
    
    this.updateImageTransform();
    
    // Update modal class for styling
    if (this.isZoomed) {
      this.modal.classList.add('zoomed');
    } else {
      this.modal.classList.remove('zoomed');
    }
  }

  updateImageTransform() {
    const img = this.modal.querySelector('img');
    const zoomContainer = this.modal.querySelector('.image-modal-zoom-container');
    
    // Only apply boundary constraints when not zoomed
    if (!this.isZoomed) {
      // Calculate boundary constraints for unzoomed state
      const containerRect = zoomContainer.getBoundingClientRect();
      const imgRect = img.getBoundingClientRect();
      
      // Calculate max pan limits based on zoom level
      const maxPanX = Math.max(0, (imgRect.width * this.zoomLevel - containerRect.width) / 2);
      const maxPanY = Math.max(0, (imgRect.height * this.zoomLevel - containerRect.height) / 2);
      
      // Constrain pan values
      this.panX = Math.max(-maxPanX, Math.min(maxPanX, this.panX));
      this.panY = Math.max(-maxPanY, Math.min(maxPanY, this.panY));
    }
    // When zoomed, allow the image to break out of bounds for natural zoom behavior
    
    const transform = `translate(${this.panX}px, ${this.panY}px) scale(${this.zoomLevel})`;
    img.style.transform = transform;
  }

  resetZoom() {
    this.zoomLevel = 1;
    this.isZoomed = false;
    this.panX = 0;
    this.panY = 0;
    this.updateImageTransform();
    this.modal.classList.remove('zoomed');
  }

  initClickableImages() {
    // Handle both new clickable-image class and legacy toggle-grow class
    const clickableImages = document.querySelectorAll('.clickable-image, .toggle-grow');
    
    clickableImages.forEach(img => {
      // Add clickable-image class for consistency
      if (!img.classList.contains('clickable-image')) {
        img.classList.add('clickable-image');
      }
      
      // Add aria-label for accessibility
      if (!img.getAttribute('aria-label')) {
        const alt = img.getAttribute('alt') || 'Image';
        img.setAttribute('aria-label', `Click to enlarge ${alt}`);
      }
      
      img.addEventListener('click', (e) => {
        e.preventDefault();
        this.open(img);
      });

      // Add keyboard support
      img.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          this.open(img);
        }
      });

      // Make images focusable for keyboard navigation
      img.setAttribute('tabindex', '0');
    });
  }

  open(imageElement) {
    this.currentImage = imageElement;
    const modalImg = this.modal.querySelector('img');
    
    // Reset zoom state
    this.resetZoom();
    
    // Set image source and alt text - use the original source for highest quality
    // Force fresh load to ensure highest quality
    const originalSrc = imageElement.src;
    modalImg.src = '';
    modalImg.src = originalSrc;
    modalImg.alt = imageElement.alt || 'Enlarged image';
    
    // Update modal aria-label with image description
    const imageDescription = imageElement.alt || 'Image';
    this.modal.setAttribute('aria-label', `Viewing ${imageDescription}`);
    
    // Open modal
    this.modal.classList.add('open');
    
    // Focus close button for accessibility
    setTimeout(() => {
      this.modal.querySelector('.image-modal-close').focus();
    }, 100);

    // Add loading state
    modalImg.style.opacity = '0';
    modalImg.onload = () => {
      modalImg.style.opacity = '1';
    };
  }

  close() {
    this.modal.classList.remove('open');
    this.currentImage = null;
    
    // Reset zoom state
    this.resetZoom();
    
    // Reset modal aria-label
    this.modal.setAttribute('aria-label', 'Image viewer');
    
    // Reset image opacity
    const modalImg = this.modal.querySelector('img');
    modalImg.style.opacity = '';
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new ImageModal();
});

// Export for potential use in other scripts
window.ImageModal = ImageModal; 