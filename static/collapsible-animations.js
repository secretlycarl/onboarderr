/**
 * Collapsible Animations JavaScript
 * 
 * This file provides smooth animations for collapsible elements
 * like accordions, expandable sections, and collapsible panels.
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize collapsible animations
    initializeCollapsibleAnimations();
});

function initializeCollapsibleAnimations() {
    // Find all collapsible elements
    const collapsibles = document.querySelectorAll('[data-collapsible]');
    
    collapsibles.forEach(collapsible => {
        const trigger = collapsible.querySelector('[data-collapsible-trigger]');
        const content = collapsible.querySelector('[data-collapsible-content]');
        
        if (trigger && content) {
            // Set initial state
            content.style.overflow = 'hidden';
            content.style.transition = 'max-height 0.3s ease-in-out, opacity 0.3s ease-in-out';
            
            // Add click handler
            trigger.addEventListener('click', function(e) {
                e.preventDefault();
                toggleCollapsible(collapsible, content);
            });
            
            // Add keyboard support
            trigger.addEventListener('keydown', function(e) {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    toggleCollapsible(collapsible, content);
                }
            });
        }
    });
}

function toggleCollapsible(collapsible, content) {
    const isExpanded = collapsible.getAttribute('data-expanded') === 'true';
    
    if (isExpanded) {
        // Collapse
        collapseElement(content);
        collapsible.setAttribute('data-expanded', 'false');
        collapsible.classList.remove('expanded');
        collapsible.classList.add('collapsed');
    } else {
        // Expand
        expandElement(content);
        collapsible.setAttribute('data-expanded', 'true');
        collapsible.classList.remove('collapsed');
        collapsible.classList.add('expanded');
    }
}

function expandElement(element) {
    // Get the natural height
    const naturalHeight = element.scrollHeight;
    
    // Set initial state
    element.style.maxHeight = '0px';
    element.style.opacity = '0';
    
    // Force reflow
    element.offsetHeight;
    
    // Animate to natural height
    element.style.maxHeight = naturalHeight + 'px';
    element.style.opacity = '1';
    
    // Clean up after animation
    setTimeout(() => {
        element.style.maxHeight = 'none';
    }, 300);
}

function collapseElement(element) {
    // Get current height
    const currentHeight = element.scrollHeight;
    
    // Set to current height
    element.style.maxHeight = currentHeight + 'px';
    
    // Force reflow
    element.offsetHeight;
    
    // Animate to 0
    element.style.maxHeight = '0px';
    element.style.opacity = '0';
}

// Utility function to create collapsible elements dynamically
function createCollapsible(triggerText, content, options = {}) {
    const collapsible = document.createElement('div');
    collapsible.className = 'collapsible';
    collapsible.setAttribute('data-collapsible', '');
    collapsible.setAttribute('data-expanded', 'false');
    
    const trigger = document.createElement('button');
    trigger.className = 'collapsible-trigger';
    trigger.setAttribute('data-collapsible-trigger', '');
    trigger.textContent = triggerText;
    
    const contentWrapper = document.createElement('div');
    contentWrapper.className = 'collapsible-content';
    contentWrapper.setAttribute('data-collapsible-content', '');
    contentWrapper.appendChild(content);
    
    collapsible.appendChild(trigger);
    collapsible.appendChild(contentWrapper);
    
    // Apply options
    if (options.className) {
        collapsible.classList.add(options.className);
    }
    
    if (options.initiallyExpanded) {
        collapsible.setAttribute('data-expanded', 'true');
        collapsible.classList.add('expanded');
        contentWrapper.style.maxHeight = 'none';
        contentWrapper.style.opacity = '1';
    }
    
    return collapsible;
}

// Export functions for use in other scripts
window.CollapsibleAnimations = {
    initialize: initializeCollapsibleAnimations,
    toggle: toggleCollapsible,
    expand: expandElement,
    collapse: collapseElement,
    create: createCollapsible
}; 