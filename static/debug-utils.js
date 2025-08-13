// Debug Utilities for Onboarderr
// Provides controlled debug logging based on JS_DEBUG environment variable

(function() {
    'use strict';
    
    // Global debug state - will be set by server-side template
    window.DEBUG_ENABLED = false;
    
    // Debug logging function
    window.debugLog = function(message, ...args) {
        if (window.DEBUG_ENABLED) {
            console.log(`[DEBUG] ${message}`, ...args);
        }
    };
    
    // Debug warning function
    window.debugWarn = function(message, ...args) {
        if (window.DEBUG_ENABLED) {
            console.warn(`[DEBUG] ${message}`, ...args);
        }
    };
    
    // Debug error function (always logs, regardless of debug state)
    window.debugError = function(message, ...args) {
        console.error(`[ERROR] ${message}`, ...args);
    };
    
    // Cleanup function to stop debug output when leaving page
    window.debugCleanup = function() {
        // Clear any intervals or timeouts that might be logging
        if (window.debugIntervals) {
            window.debugIntervals.forEach(intervalId => {
                clearInterval(intervalId);
            });
            window.debugIntervals = [];
        }
        
        if (window.debugTimeouts) {
            window.debugTimeouts.forEach(timeoutId => {
                clearTimeout(timeoutId);
            });
            window.debugTimeouts = [];
        }
        
        debugLog('Debug cleanup completed');
    };
    
    // Helper to track intervals for cleanup
    window.debugSetInterval = function(callback, delay, ...args) {
        const intervalId = setInterval(callback, delay, ...args);
        if (!window.debugIntervals) {
            window.debugIntervals = [];
        }
        window.debugIntervals.push(intervalId);
        return intervalId;
    };
    
    // Helper to track timeouts for cleanup
    window.debugSetTimeout = function(callback, delay, ...args) {
        const timeoutId = setTimeout(callback, delay, ...args);
        if (!window.debugTimeouts) {
            window.debugTimeouts = [];
        }
        window.debugTimeouts.push(timeoutId);
        return timeoutId;
    };
    
    // Initialize debug state from server
    document.addEventListener('DOMContentLoaded', function() {
        // Debug state will be set by server-side template
        debugLog('Debug utilities initialized');
    });
    
    // Cleanup on page unload
    window.addEventListener('beforeunload', function() {
        debugCleanup();
    });
    
    // Cleanup on page visibility change (when user switches tabs)
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            debugLog('Page hidden - reducing debug output');
        } else {
            debugLog('Page visible - resuming debug output');
        }
    });
    
})(); 