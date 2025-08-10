# App.py Refactoring Plan

## Overview
This document outlines potential improvements for `app.py`, a 6000+ line Flask application for managing media server access requests. The code is functionally sound but would benefit from structural improvements for maintainability, testability, and scalability.

## High Priority Improvements

### 1. **Modular Architecture**
**Current State**: Single monolithic file (6000+ lines)
**Problem**: Difficult to navigate, maintain, and test

**Solution**: Split into logical modules:
```
onboarderr/
├── app.py                 # Main application entry point
├── routes/
│   ├── __init__.py
│   ├── auth.py           # Login, logout, setup routes
│   ├── onboarding.py     # Plex onboarding routes
│   ├── audiobookshelf.py # ABS routes
│   ├── services.py       # Admin services routes
│   ├── api.py            # AJAX/API endpoints
│   └── media.py          # Media-related routes
├── services/
│   ├── __init__.py
│   ├── plex_service.py   # Plex API interactions
│   ├── abs_service.py    # Audiobookshelf API interactions
│   ├── poster_service.py # Poster download logic
│   ├── security_service.py # Rate limiting, IP management
│   └── notification_service.py # Discord notifications
├── utils/
│   ├── __init__.py
│   ├── file_utils.py     # File operations
│   ├── image_utils.py    # Image processing
│   ├── crypto_utils.py   # Password/API key handling
│   └── validation_utils.py # Input validation
├── models/
│   ├── __init__.py
│   ├── user.py           # User data structures
│   ├── library.py        # Library data structures
│   └── submission.py     # Form submission structures
├── config/
│   ├── __init__.py
│   ├── settings.py       # Configuration management
│   └── constants.py      # Application constants
└── tests/                # Test suite
```

### 2. **State Management**
**Current State**: Global variables scattered throughout
```python
# Current problematic pattern
poster_download_queue = queue.Queue()
poster_download_lock = Lock()
poster_download_running = False
poster_download_progress = {}
rate_limit_data = {...}
library_cache = {}
library_cache_timestamp = 0
library_cache_lock = Lock()
```

**Solution**: Application state class
```python
class AppState:
    def __init__(self):
        self.poster_download_queue = queue.Queue()
        self.poster_download_lock = Lock()
        self.poster_download_running = False
        self.poster_download_progress = {}
        self.rate_limit_data = {...}
        self.library_cache = {}
        self.library_cache_timestamp = 0
        self.library_cache_lock = Lock()
    
    def reset_poster_state(self):
        self.poster_download_running = False
        self.poster_download_progress.clear()
```

## Medium Priority Improvements

### 3. **Configuration Management**
**Current State**: Direct environment variable access throughout code
```python
# Current pattern
APP_PORT = int(os.getenv("APP_PORT"))
debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
RESTART_DELAY_SECONDS = int(os.getenv("RESTART_DELAY_SECONDS", "5"))
```

**Solution**: Centralized configuration class
```python
class Config:
    def __init__(self):
        load_dotenv()
        self.app_port = int(os.getenv("APP_PORT"))
        self.debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
        self.restart_delay = int(os.getenv("RESTART_DELAY_SECONDS", "5"))
        self.poster_timeout = int(os.getenv("POSTER_DOWNLOAD_TIMEOUT", "300"))
        self.library_cache_ttl = int(os.getenv("LIBRARY_CACHE_TTL", "86400"))
    
    def reload(self):
        load_dotenv(override=True)
        self.__init__()
```

### 4. **Function Decomposition**
**Current State**: Several very long functions (100+ lines)
- `onboarding()` - ~100 lines
- `services()` - ~200 lines
- `download_and_cache_posters()` - ~100 lines

**Solution**: Break into smaller, focused functions
```python
# Instead of one large function
def onboarding():
    # 100+ lines of mixed logic
    
# Break into focused functions
def onboarding():
    if not is_authenticated():
        return redirect_to_login()
    
    if request.method == "POST":
        return handle_onboarding_submission()
    
    context = build_onboarding_context()
    return render_template("onboarding.html", **context)

def handle_onboarding_submission():
    # Handle form submission logic
    
def build_onboarding_context():
    # Build template context
```

### 5. **Error Handling Standardization**
**Current State**: Inconsistent error handling patterns
```python
# Some functions have comprehensive error handling
try:
    # ... code
except Exception as e:
    if debug_mode:
        print(f"Error: {e}")
    return False

# Others have minimal or no error handling
def some_function():
    # No error handling
    return result
```

**Solution**: Standardized error handling decorator
```python
def handle_errors(default_return=None, log_errors=True):
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_errors and current_app.config.get('DEBUG'):
                    current_app.logger.error(f"Error in {func.__name__}: {e}")
                return default_return
        return wrapper
    return decorator

@handle_errors(default_return=False)
def risky_function():
    # Function with automatic error handling
    pass
```

## Low Priority Improvements

### 6. **Magic Numbers and Strings**
**Current State**: Hardcoded values throughout
```python
# Current
RESTART_DELAY_SECONDS = int(os.getenv("RESTART_DELAY_SECONDS", "5"))
POSTER_DOWNLOAD_TIMEOUT = int(os.getenv("POSTER_DOWNLOAD_TIMEOUT", "300"))
LIBRARY_CACHE_TTL = 86400  # 24 hour cache
```

**Solution**: Configuration constants
```python
class Constants:
    # Time constants
    DEFAULT_RESTART_DELAY = 5
    DEFAULT_POSTER_TIMEOUT = 300
    DEFAULT_LIBRARY_CACHE_TTL = 86400  # 24 hours
    DEFAULT_LOCKOUT_DURATION = 3600    # 1 hour
    
    # Rate limiting constants
    DEFAULT_MAX_LOGIN_ATTEMPTS = 5
    DEFAULT_SUSPICIOUS_THRESHOLD = 20
    DEFAULT_BAN_THRESHOLD = 50
    
    # File constants
    DEFAULT_IMAGE_QUALITY = 95
    DEFAULT_FAVICON_SIZE = 32
```

### 7. **Code Duplication Elimination**
**Current State**: Similar patterns repeated across routes
```python
# Similar form processing in multiple routes
if request.method == "POST":
    client_ip = get_client_ip()
    is_rate_limited, remaining_time = check_rate_limit(client_ip, "form_submission", "plex")
    if is_rate_limited:
        # Similar rate limiting logic
```

**Solution**: Shared utility functions
```python
def handle_form_submission(form_type, process_func):
    """Generic form submission handler with rate limiting"""
    client_ip = get_client_ip()
    is_rate_limited, remaining_time = check_rate_limit(client_ip, "form_submission", form_type)
    
    if is_rate_limited:
        time_remaining = format_time_remaining(remaining_time)
        log_security_event("form_rate_limited", client_ip, f"{form_type} form submission rate limited")
        return handle_rate_limited_response(time_remaining)
    
    return process_func()

def handle_rate_limited_response(remaining_time):
    """Standard rate limiting response"""
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": False, "error": f"Too many submissions. Please try again in {remaining_time}."})
    else:
        return render_template("error.html", error=f"Too many submissions. Please try again in {remaining_time}.")
```

### 8. **Input Validation**
**Current State**: Minimal input validation
**Solution**: Comprehensive validation decorators
```python
from functools import wraps
from flask import request, jsonify

def validate_form_fields(required_fields, optional_fields=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            missing_fields = []
            for field in required_fields:
                if not request.form.get(field):
                    missing_fields.append(field)
            
            if missing_fields:
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return jsonify({"success": False, "error": f"Missing required fields: {', '.join(missing_fields)}"})
                else:
                    return render_template("error.html", error=f"Missing required fields: {', '.join(missing_fields)}")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@validate_form_fields(["email", "libraries"])
def onboarding():
    # Function with automatic validation
    pass
```

## Implementation Strategy

### Phase 1: Import Organization ✅
- [x] Reorganize imports into logical groups
- [x] Add proper spacing and comments

### Phase 2: Configuration Management
- [ ] Create Config class
- [ ] Replace direct os.getenv() calls
- [ ] Add configuration validation

### Phase 3: State Management
- [ ] Create AppState class
- [ ] Move global variables to state class
- [ ] Update functions to use state class

### Phase 4: Function Decomposition
- [ ] Break down large functions
- [ ] Extract common logic to utility functions
- [ ] Create focused, single-responsibility functions

### Phase 5: Module Splitting
- [ ] Create directory structure
- [ ] Move routes to separate files
- [ ] Move services to separate files
- [ ] Move utilities to separate files

### Phase 6: Testing and Validation
- [ ] Add unit tests for extracted functions
- [ ] Add integration tests for routes
- [ ] Validate all functionality works as expected

## Benefits of Refactoring

1. **Maintainability**: Easier to find and modify specific functionality
2. **Testability**: Smaller, focused functions are easier to test
3. **Readability**: Clearer separation of concerns
4. **Reusability**: Common functionality can be shared across routes
5. **Scalability**: Easier to add new features and developers
6. **Debugging**: Isolated functions are easier to debug
7. **Documentation**: Smaller modules are easier to document

## Risk Assessment

**Low Risk**:
- Import organization
- Configuration management
- Magic number extraction

**Medium Risk**:
- Function decomposition
- State management refactoring

**High Risk**:
- Module splitting (requires careful testing)

## Conclusion

The current `app.py` is a well-functioning application that would benefit significantly from structural improvements. The refactoring should be done incrementally, starting with low-risk changes and progressing to more complex restructuring. Each phase should be thoroughly tested before proceeding to the next.

The end result will be a more maintainable, testable, and scalable codebase that retains all current functionality while being much easier to work with. 