# Security Improvements TODO List

## Overview
Comprehensive security enhancements for Onboarderr, focusing on rate limiting, user access control, audit logging, and enhanced authentication while maintaining backward compatibility.

## Phase 1: Core Security (High Priority)

### Rate Limiting Implementation
- [x] **Add Flask-Limiter dependency**
  - [x] Add to requirements.txt
  - [x] Configure rate limiting middleware
  - [x] Implement IP-based tracking

- [x] **Login Rate Limiting**
  - [x] 5 attempts per 15 minutes
  - [x] 1 hour lockout after 5 failed attempts
  - [x] Progressive delays (1min, 5min, 15min, 1hr)
  - [x] Track failed attempts per IP
  - [x] Apply to both password and PIN authentication

- [x] **Form Submission Rate Limiting**
  - [x] 1 submission per hour per form type (Plex/Audiobookshelf)
  - [x] Separate limits for different forms
  - [x] Prevent duplicate submissions (server-side)
  - [x] Add submission timestamps and IP tracking

- [x] **IP Monitoring**
  - [x] Track suspicious IP patterns
  - [x] Manual IP whitelist/blacklist in admin panel (implemented)
  - [x] Monitor for brute force attempts
  - [x] Alert admin on suspicious activity

### PIN Code System
- [ ] **PIN Code Implementation**
  - [ ] 6-digit numeric PIN codes
  - [ ] Admin PIN (full access)
  - [ ] Public PIN (standard user access)
  - [ ] Rate limiting for PIN attempts (5 per 15 minutes)
  - [ ] 1 hour lockout after failed attempts

- [ ] **PIN Code Management**
  - [ ] Generate secure random PINs
  - [ ] Allow admin to set custom PINs
  - [ ] PIN expiry configuration (never, 1day, 7days, 30days, 90days)
  - [ ] PIN rotation capabilities

- [ ] **Backward Compatibility**
  - [ ] Keep existing password system functional
  - [ ] Allow both passwords and PINs to work
  - [ ] Gradual migration path
  - [ ] No forced changes for existing users

### Audit Logging System
- [x] **Log File Structure**
  - [x] `security_log.json`: Login attempts, security events
  - [ ] `form_submissions_log.json`: Form submission tracking
  - [ ] `access_code_usage.json`: Access code usage
  - [ ] `ip_monitoring.json`: Suspicious IP activity

- [x] **Logging Events**
  - [x] All login attempts (success/failure)
  - [x] Form submissions with IP and timestamp
  - [x] Rate limiting events
  - [ ] PIN code usage
  - [ ] Access code usage
  - [x] Suspicious activity detection

- [x] **Log Management**
  - [x] 90-day log retention
  - [x] Log rotation
  - [ ] Export functionality
  - [x] Admin notification system

### Enhanced Session Security
- [ ] **Session Management**
  - [ ] 8-hour session timeout
  - [ ] Concurrent session limits (3 max)
  - [ ] Session invalidation on security events
  - [ ] Device fingerprinting for session tracking

- [ ] **Session Configuration**
  - [ ] Configurable timeout settings
  - [ ] Session security options
  - [ ] Concurrent session limits

## Phase 2: User Groups & Access Control (Medium Priority)

### User Group System (Optional)
- [ ] **User Group Configuration**
  - [ ] Enable/disable user groups feature
  - [ ] Create/edit user groups in admin panel
  - [ ] Assign libraries to specific groups
  - [ ] Set carousel visibility per group
  - [ ] Configure tab access permissions

- [ ] **Access Code System**
  - [ ] 6-character alphanumeric access codes (A-Z, 0-9)
  - [ ] Generate unique codes per user group
  - [ ] Time-limited codes with configurable expiry
  - [ ] Code rotation capabilities
  - [ ] Fallback to regular password system

- [ ] **Group-Specific PIN Codes**
  - [ ] 6-digit PIN codes per user group
  - [ ] Configurable expiry times per group
  - [ ] Rate limiting per group
  - [ ] Group-specific library access

### Library Access Control
- [ ] **Library Assignment System**
  - [ ] Assign libraries to user groups
  - [ ] Filter carousels by group access
  - [ ] Filter media lists by group access
  - [ ] Filter form submissions by group access
  - [ ] Hidden libraries (admin only)

- [ ] **Access Level Configuration**
  - [ ] Admin: Full access to services, all libraries
  - [ ] Public: All regular libraries, no hidden ones
  - [ ] Unique Groups: Specific libraries only
  - [ ] Tab access permissions (Plex/Audiobookshelf)

### Admin Interface Enhancements
- [ ] **Security Settings Section**
  - [ ] Rate limiting configuration
  - [ ] PIN code settings
  - [ ] Audit logging options
  - [ ] Public access settings

- [ ] **User Groups Section**
  - [ ] Enable/disable user groups
  - [ ] Create/edit groups
  - [ ] Assign libraries to groups
  - [ ] Generate access codes and PINs
  - [ ] Set expiry times

- [ ] **Access Control Section**
  - [ ] Library assignment per group
  - [ ] Carousel visibility settings
  - [ ] Tab access permissions
  - [ ] Code management

- [ ] **Audit & Monitoring Section**
  - [ ] View security logs
  - [ ] Monitor failed attempts
  - [ ] Track form submissions
  - [ ] Export security data

## Phase 3: Advanced Features (Lower Priority)

### Public Access Options
- [ ] **"No Login" Public Access**
  - [ ] Option to remove site password entirely
  - [ ] Direct access to onboarding pages
  - [ ] Admin access still protected via /services
  - [ ] IP whitelist for trusted networks

- [ ] **Admin Access Protection**
  - [ ] /services always requires authentication
  - [ ] Support for admin password (legacy)
  - [ ] Support for admin PIN code (new)
  - [ ] Rate limiting for admin access

### Advanced Security Features
- [ ] **IP Monitoring & Blocking**
  - [ ] Manual IP whitelist/blacklist
  - [ ] Suspicious IP detection
  - [ ] Admin notification system
  - [ ] IP-based rate limiting

- [ ] **Security Notifications**
  - [ ] Discord notifications for security events
  - [ ] Email notifications (if configured)
  - [ ] Admin dashboard alerts
  - [ ] Security event summaries

### Enhanced Monitoring
- [ ] **Advanced Audit Features**
  - [ ] Real-time security monitoring
  - [ ] Security event correlation
  - [ ] Threat detection algorithms
  - [ ] Security report generation

## Configuration Settings

### New Environment Variables
```python
# Rate limiting settings
RATE_LIMIT_LOGIN_ATTEMPTS=5
RATE_LIMIT_LOGIN_LOCKOUT_DURATION=3600
RATE_LIMIT_FORM_SUBMISSIONS=1
RATE_LIMIT_PIN_ATTEMPTS=5
RATE_LIMIT_ACCESS_CODE_ATTEMPTS=10
RATE_LIMIT_IP_SUSPICIOUS_THRESHOLD=20
RATE_LIMIT_IP_BAN_THRESHOLD=50

# PIN code settings
ENABLE_PIN_CODES=yes
PIN_CODE_LENGTH=6
PIN_CODE_MAX_ATTEMPTS=5
PIN_CODE_LOCKOUT_DURATION=3600
ADMIN_PIN_EXPIRY=never
PUBLIC_PIN_EXPIRY=never

# User group settings
ENABLE_USER_GROUPS=no
USER_GROUP_ACCESS_CODE_LENGTH=6
USER_GROUP_PIN_CODE_LENGTH=6
USER_GROUP_EXPIRY_OPTIONS=never,1day,7days,30days,90days

# Audit logging
ENABLE_AUDIT_LOGGING=yes
AUDIT_LOG_RETENTION_DAYS=90
LOG_FAILED_LOGIN_ATTEMPTS=yes
LOG_FORM_SUBMISSIONS=yes
LOG_IP_ADDRESSES=yes
NOTIFY_ADMIN_ON_SECURITY_EVENTS=yes

# Session settings
SESSION_TIMEOUT_MINUTES=480
MAX_CONCURRENT_SESSIONS=3
ENABLE_SESSION_FINGERPRINTING=yes

# Public access settings
ENABLE_PUBLIC_ACCESS=no
BYPASS_SITE_PASSWORD=no
ADMIN_ACCESS_ALWAYS_PROTECTED=yes
```

## Implementation Notes

### Backward Compatibility
- [ ] All existing passwords continue to work
- [ ] Current form submission system preserved
- [ ] Existing library setup maintained
- [ ] Gradual migration to new system
- [ ] No forced changes for existing users

### Migration Strategy
- [ ] Install new security features
- [ ] Keep existing passwords functional
- [ ] Optionally enable PIN codes
- [ ] Optionally enable user groups
- [ ] Migrate users gradually

### Testing Requirements
- [ ] Test rate limiting functionality
- [ ] Test PIN code system
- [ ] Test user group access control
- [ ] Test audit logging
- [ ] Test backward compatibility
- [ ] Test form submission throttling
- [ ] Test session management
- [ ] Test admin interface enhancements

## File Structure Changes

### New Files to Create
- [ ] `security_log.json` - Security event logging
- [ ] `form_submissions_log.json` - Form submission tracking
- [ ] `access_code_usage.json` - Access code usage
- [ ] `ip_monitoring.json` - IP activity monitoring
- [ ] `user_groups.json` - User group configuration
- [ ] `security_config.json` - Security settings

### Files to Modify
- [ ] `app.py` - Add security middleware and functions
- [ ] `requirements.txt` - Add Flask-Limiter dependency
- [ ] `empty.env` - Add new environment variables
- [ ] `templates/services.html` - Add security settings sections
- [ ] `templates/login.html` - Add PIN code support

## Dependencies to Add
- [ ] Flask-Limiter (rate limiting)
- [ ] Additional security libraries as needed

## Security Considerations
- [ ] Ensure all PIN codes are cryptographically secure
- [ ] Implement proper session management
- [ ] Validate all user inputs
- [ ] Protect against CSRF attacks
- [ ] Implement proper error handling
- [ ] Ensure audit logs cannot be tampered with
- [ ] Implement proper access control checks

## Documentation Updates
- [ ] Update README with security features
- [ ] Add security configuration guide
- [ ] Document user group setup process
- [ ] Add troubleshooting guide for security issues
- [ ] Update setup instructions for new features 