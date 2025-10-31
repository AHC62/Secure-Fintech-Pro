# Secure FinTech Application - Manual Testing Instructions

## Prerequisites
1. Install required packages:
```bash
pip install flask bcrypt cryptography werkzeug
```

2. Run the application:
```bash
python app.py
```

3. Open browser and go to: `http://localhost:5000`

## 20+ Manual Security Test Cases

### Test Case 1: SQL Injection - Login Form
**Action:** Enter `' OR 1=1--` in username field, any password
**Expected:** Input rejected/error handled properly
**Steps:**
1. Go to login page
2. Username: `' OR 1=1--`
3. Password: `test123`
4. Click Login
**Pass Criteria:** Generic error message, no database exposure

### Test Case 2: Password Strength Validation
**Action:** Try weak password during registration
**Expected:** Password rejected with specific requirements
**Steps:**
1. Go to register page
2. Username: `testuser`
3. Email: `test@email.com`
4. Password: `12345`
5. Confirm Password: `12345`
6. Click Register
**Pass Criteria:** Error showing password requirements

### Test Case 3: XSS Prevention - Username Input
**Action:** Enter `<script>alert('XSS')</script>` in username
**Expected:** Script tags sanitized/escaped
**Steps:**
1. Go to register page
2. Username: `<script>alert('XSS')</script>`
3. Fill other fields normally
4. Submit form
**Pass Criteria:** No JavaScript execution, input sanitized

### Test Case 4: Unauthorized Access - Direct URL
**Action:** Access `/dashboard` without login
**Expected:** Redirected to login page
**Steps:**
1. Open new browser tab
2. Go to `http://localhost:5000/dashboard`
**Pass Criteria:** Automatically redirected to login

### Test Case 5: Session Timeout
**Action:** Stay idle for 30+ minutes
**Expected:** Auto logout, session cleared
**Steps:**
1. Login successfully
2. Wait 31 minutes without activity
3. Try to access any protected page
**Pass Criteria:** Session expired message, redirected to login

### Test Case 6: Logout Functionality
**Action:** Click logout button
**Expected:** Session destroyed, redirect to login
**Steps:**
1. Login successfully
2. Click "Logout" in navigation
**Pass Criteria:** Logged out, cannot access protected pages

### Test Case 7: Data Confidentiality Check
**Action:** Check if passwords are hashed in database
**Expected:** Passwords stored as hashes, not plaintext
**Steps:**
1. Register a new user
2. Check `fintech_app.db` file using SQLite browser
3. Look at `users` table
**Pass Criteria:** Password_hash column contains bcrypt hashes

### Test Case 8: File Upload Validation
**Action:** Try uploading .exe file
**Expected:** File rejected with error message
**Steps:**
1. Login and go to upload page
2. Select a .exe file
3. Click upload
**Pass Criteria:** Error message about invalid file type

### Test Case 9: Error Message Information Leakage
**Action:** Force an application error
**Expected:** Generic error, no stack trace exposed
**Steps:**
1. Try accessing `/nonexistent_page`
2. Check error response
**Pass Criteria:** Generic 404 page, no technical details

### Test Case 10: Input Length Validation
**Action:** Enter 5000+ characters in description field
**Expected:** Input validation triggered
**Steps:**
1. Go to transaction page
2. Description field: Paste 5000+ characters
3. Submit form
**Pass Criteria:** Validation error about length limit

### Test Case 11: Duplicate User Registration
**Action:** Register with existing username
**Expected:** Clear error message shown
**Steps:**
1. Register user: `admin`
2. Try registering another user with username: `admin`
**Pass Criteria:** "Username already exists" error

### Test Case 12: Numeric Field Validation
**Action:** Enter letters in amount field
**Expected:** Validation error shown
**Steps:**
1. Go to transaction page
2. Amount field: `abc123xyz`
3. Submit form
**Pass Criteria:** "Invalid numeric value" error

### Test Case 13: Password Confirmation Match
**Action:** Enter mismatched confirm password
**Expected:** Registration blocked
**Steps:**
1. Go to register page
2. Password: `SecurePass123!`
3. Confirm Password: `DifferentPass456!`
4. Submit
**Pass Criteria:** "Passwords do not match" error

### Test Case 14: Data Modification Attempt
**Action:** Manually change transaction ID in URL
**Expected:** Access denied or data protection
**Steps:**
1. Login and view a transaction
2. Change URL from `/transaction/1` to `/transaction/999`
**Pass Criteria:** Access denied or shows only user's data

### Test Case 15: Email Format Validation
**Action:** Enter invalid email format
**Expected:** Validation error displayed
**Steps:**
1. Go to register page
2. Email: `abc@`
3. Submit form
**Pass Criteria:** "Invalid email format" error

### Test Case 16: Brute Force Protection
**Action:** 5+ failed login attempts
**Expected:** Account locked temporarily
**Steps:**
1. Try login with wrong password 5 times
2. Try 6th attempt
**Pass Criteria:** Account lockout message

### Test Case 17: Secure Error Handling
**Action:** Force divide-by-zero or similar error
**Expected:** App doesn't crash, controlled message
**Steps:**
1. Try to trigger application error through input manipulation
**Pass Criteria:** Graceful error handling, no crash

### Test Case 18: Encrypted Data Storage
**Action:** Check stored sensitive data
**Expected:** Data encrypted/unreadable
**Steps:**
1. Add transaction with notes
2. Check database file
3. Look at encrypted_notes column
**Pass Criteria:** Data appears encrypted, not readable

### Test Case 19: Unicode/Special Character Handling
**Action:** Use Unicode emoji in input fields
**Expected:** App handles gracefully
**Steps:**
1. Username: `test🔒user`
2. Description: `Money💰transfer`
3. Submit forms
**Pass Criteria:** No corruption or errors

### Test Case 20: Empty Field Submission
**Action:** Submit forms with required fields blank
**Expected:** Validation warnings displayed
**Steps:**
1. Go to any form
2. Leave required fields empty
3. Submit
**Pass Criteria:** "Field required" messages

### Test Case 21: Session Hijacking Protection
**Action:** Copy session cookie to different browser
**Expected:** Session validation prevents unauthorized access
**Steps:**
1. Login in Browser A
2. Copy session cookie to Browser B
3. Try accessing protected pages in Browser B
**Pass Criteria:** Access denied or re-authentication required

### Test Case 22: CSRF Protection Test
**Action:** Submit form from external source
**Expected:** Request rejected due to CSRF protection
**Steps:**
1. Create external HTML form targeting your app
2. Submit form from different domain
**Pass Criteria:** Request blocked or validation failed

### Test Case 23: Input Encoding Attack
**Action:** Try URL encoding in input fields
**Expected:** Proper decoding and validation
**Steps:**
1. Username: `%3Cscript%3Ealert%281%29%3C/script%3E`
2. Submit form
**Pass Criteria:** Input properly handled, no script execution

### Test Case 24: File Path Traversal
**Action:** Try accessing system files through upload
**Expected:** Path traversal blocked
**Steps:**
1. Try uploading file with name: `../../../etc/passwd`
**Pass Criteria:** File name sanitized, path traversal prevented

### Test Case 25: Account Enumeration
**Action:** Check if usernames can be enumerated
**Expected:** Generic responses for login attempts
**Steps:**
1. Try login with non-existent username
2. Try login with existing username but wrong password
**Pass Criteria:** Same generic error message for both

## Documentation Requirements

For each test, document:
1. **Test Number & Name**
2. **Action Performed** (exact steps)
3. **Expected Outcome**
4. **Observed Result**
5. **Pass/Fail Status**
6. **Screenshot** (if applicable)

## Sample Test Documentation Format:

| No. | Test Case | Action Performed | Expected Outcome | Observed Result | Pass/Fail |
|-----|-----------|------------------|------------------|-----------------|-----------|
| 1   | SQL Injection - Login | Entered 'OR 1=1-- in username | Input rejected/error handled | Generic error shown, no DB access | PASS |
| 2   | Password Strength | Tried password: 12345 | Password rejected | "Password must be at least 8 characters" shown | PASS |

## Additional Testing Tips:

1. **Use Browser Developer Tools** to inspect network requests
2. **Check Database Files** to verify encryption/hashing
3. **Test in Multiple Browsers** for consistency
4. **Use Incognito/Private Mode** for fresh sessions
5. **Monitor Console Errors** during testing
6. **Test Both Valid and Invalid Inputs**
7. **Verify Audit Logs** are properly recorded
8. **Test Edge Cases** (very long inputs, special characters)

## Security Verification Checklist:

- [ ] All passwords are bcrypt hashed
- [ ] Sensitive data is encrypted
- [ ] Input validation prevents injection
- [ ] Sessions timeout properly
- [ ] File uploads are restricted
- [ ] Error messages don't leak information
- [ ] Audit logs track all actions
- [ ] Authentication is required for protected areas
- [ ] User input is sanitized
- [ ] Rate limiting prevents brute force

## Reporting Format:

Create a document with:
1. **Executive Summary** of security testing
2. **Test Environment Details**
3. **Individual Test Results** (table format)
4. **Screenshots** of key tests
5. **Security Findings** and recommendations
6. **Conclusion** on app security posture

This comprehensive testing approach will demonstrate thorough manual cybersecurity testing of your FinTech application.
