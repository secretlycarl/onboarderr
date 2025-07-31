// Image Modal System
class ImageModal {
  constructor() {
    this.modal = null;
    this.currentImage = null;
    this.touchStartX = 0;
    this.touchStartY = 0;
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
        <img src="" alt="Enlarged image">
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

    this.modal.addEventListener('touchstart', (e) => {
      startX = e.touches[0].clientX;
      startY = e.touches[0].clientY;
      currentX = startX;
      currentY = startY;
    }, { passive: true });

    this.modal.addEventListener('touchmove', (e) => {
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
    }, { passive: false });

    this.modal.addEventListener('touchend', () => {
      startX = startY = 0;
    }, { passive: true });
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
    
    // Set image source and alt text
    modalImg.src = imageElement.src;
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